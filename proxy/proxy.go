package proxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/dns"
	"github.com/xssnick/tonutils-proxy/proxy/transport"
	"github.com/xssnick/tonutils-storage/storage"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

// Hop-by-hop headers (RFC 2616 §13) plus privacy-sensitive headers.
// Privacy headers follow Privoxy/Tor Browser stripping conventions.
var hopHeaders = []string{
	// RFC 2616 hop-by-hop
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
	// Privacy: tracking vectors
	"Origin",
	"Referer",
	// Privacy: proxy topology leaks
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Real-Ip",
	"Forwarded",
	"Via",
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func delHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}


type proxy struct {
	version   string
	blockHttp bool
}

var client *http.Client

func (p *proxy) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	if req.URL.Scheme == "" {
		// if no scheme - we check forwarded proto
		req.URL.Scheme = req.Header.Get("X-Forwarded-Proto")
	}

	if req.Method == "CONNECT" {
		log.Debug().Str("host", req.Host).Msg("CONNECT not supported")
		http.Error(wr, "CONNECT not supported", http.StatusMethodNotAllowed)
		return
	}

	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}

	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		msg := "unsupported protocol scheme " + req.URL.Scheme
		http.Error(wr, msg, http.StatusBadRequest)
		return
	}

	//http: Request.RequestURI can't be set in client requests.
	//http://golang.org/src/pkg/net/http/client.go
	req.RequestURI = ""

	delHopHeaders(req.Header)

	req.Header.Set("X-Tonutils-Proxy", p.version)

	var c = http.DefaultClient
	urlHost := req.URL.Host
	if strings.HasSuffix(req.Host, ".ton") || strings.HasSuffix(req.Host, ".adnl") ||
		strings.HasSuffix(req.Host, ".t.me") || strings.HasSuffix(req.Host, ".bag") ||
		strings.HasSuffix(urlHost, ".adnl") {
		log.Debug().Str("method", req.Method).Str("url", req.URL.String()).Msg("over rldp")
		// proxy requests to ton using special client
		c = client
	} else {
		if p.blockHttp {
			http.Error(wr, "HTTP Not allowed", http.StatusBadRequest)
			return
		}

		log.Debug().Str("method", req.Method).Str("url", req.URL.String()).Msg("over http")
	}

	resp, err := c.Do(req)
	if err != nil {
		text := err.Error()
		if strings.Contains(text, "context deadline exceeded") {
			http.Error(wr, "TON Site "+req.URL.Host+" is not responding.", http.StatusBadGateway)
		} else {
			http.Error(wr, "RLDP Proxy Error:\n"+text, http.StatusBadGateway)
		}
		log.Warn().Str("err", text).Str("method", req.Method).Msg("RLDP request failed")
		return
	}
	defer resp.Body.Close()

	log.Debug().Str("status", resp.Status).Str("addr", req.RemoteAddr).Msg("loading")

	delHopHeaders(resp.Header)

	copyHeader(wr.Header(), resp.Header)
	wr.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(wr, io.LimitReader(resp.Body, 100<<20)); err != nil {
		log.Debug().Err(err).Str("url", req.URL.String()).Msg("response copy interrupted")
	}
}

type State struct {
	Type    string
	State   string
	Stopped bool
}

func RunProxy(closerCtx context.Context, addr string, adnlKey ed25519.PrivateKey, res chan<- State, versionAndDevice string, blockHttp bool, netConfigPath string) error {
	if res != nil {
		res <- State{
			Type:  "loading",
			State: "Fetching network config...",
		}
	}

	var err error
	var lsCfg *liteclient.GlobalConfig
	if netConfigPath != "" {
		log.Info().Msg("Fetching TON network config from disk...")
		lsCfg, err = liteclient.GetConfigFromFile(netConfigPath)
		if err != nil {
			return fmt.Errorf("failed to parse ton config: %w", err)
		}
	} else {
		log.Info().Msg("Fetching TON network config...")
		lsCfg, err = liteclient.GetConfigFromUrl(context.Background(), "https://ton-blockchain.github.io/global.config.json")
		if err != nil {
			log.Error().Err(err).Msg("Failed to download ton config; taking it from static cache")
			lsCfg = &liteclient.GlobalConfig{}
			if err = json.NewDecoder(bytes.NewBufferString(fallbackNetworkConfig)).Decode(lsCfg); err != nil {
				return fmt.Errorf("failed to parse fallback ton config: %w", err)
			}
		}
	}

	return RunProxyWithConfig(closerCtx, addr, adnlKey, res, blockHttp, versionAndDevice, lsCfg)
}

func RunProxyWithConfig(closerCtx context.Context, addr string, adnlKey ed25519.PrivateKey, res chan<- State, blockHttp bool, versionAndDevice string, lsCfg *liteclient.GlobalConfig) error {
	report := func(s State) {
		if res != nil {
			res <- s
		}
	}

	var err error
	if len(adnlKey) == 0 {
		_, adnlKey, err = ed25519.GenerateKey(nil)
		if err != nil {
			return fmt.Errorf("failed to generate ed25519 adnl key: %w", err)
		}
	}

	ctx, closer := context.WithCancel(closerCtx)
	defer closer()

	report(State{
		Type:  "loading",
		State: "Initializing DNS...",
	})

	log.Info().Msg("Initializing DNS resolver...")
	connPool, dnsClient, err := initDNSResolver(lsCfg)
	if err != nil {
		return fmt.Errorf("failed to init TON DNS resolver: %w", err)
	}
	defer connPool.Stop()

	var gate *adnl.Gateway
	var netMgr adnl.NetManager

	dl, err := adnl.DefaultListener(":")
	if err != nil {
		log.Error().Err(err).Msg("Failed to create default listener")
		return err
	}
	netMgr = adnl.NewMultiNetReader(dl)
	gate = adnl.NewGatewayWithNetManager(adnlKey, netMgr)
	defer gate.Close()
	defer netMgr.Close()

	listenThreads := runtime.NumCPU()
	if listenThreads > 32 {
		listenThreads = 32
	}

	report(State{
		Type:  "loading",
		State: "Initializing DHT...",
	})

	log.Info().Msg("Initializing DHT client...")
	_, dhtAdnlKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("failed to generate ed25519 dht adnl key: %w", err)
	}

	gateway := adnl.NewGatewayWithNetManager(dhtAdnlKey, netMgr)
	err = gateway.StartClient()
	if err != nil {
		return fmt.Errorf("failed to start adnl gateway: %w", err)
	}
	defer gateway.Close()

	dhtClient, err := dht.NewClientFromConfig(gateway, lsCfg)
	if err != nil {
		return fmt.Errorf("failed to init DHT client: %w", err)
	}
	defer dhtClient.Close()

	report(State{
		Type:  "loading",
		State: "Initializing RLDP...",
	})

	log.Info().Msg("Initializing RLDP transport layer...")
	_, storageAdnlKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("failed to generate ed25519 storage adnl key: %w", err)
	}
	_, proxyAdnlKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("failed to generate ed25519 proxy adnl key: %w", err)
	}

	gateStorage := adnl.NewGatewayWithNetManager(storageAdnlKey, netMgr)
	if err = gateStorage.StartClient(listenThreads); err != nil {
		return fmt.Errorf("failed to init adnl gateway: %w", err)
	}
	defer gateStorage.Close()

	srv := storage.NewServer(dhtClient, gateStorage, storageAdnlKey, false, 1)
	conn := storage.NewConnector(srv)

	store := transport.NewVirtualStorage()
	srv.SetStorage(store)

	defer srv.Stop()

	gateProxy := adnl.NewGatewayWithNetManager(proxyAdnlKey, netMgr)
	if err = gateProxy.StartClient(listenThreads); err != nil {
		return fmt.Errorf("failed to init adnl gateway for proxy: %w", err)
	}
	defer gateProxy.Close()

	report(State{
		Type:  "loading",
		State: "Starting HTTP server...",
	})

	t := transport.NewTransport(gateProxy, dhtClient, dnsClient, conn, store)
	client = &http.Client{
		Transport: t,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer t.Stop()

	log.Info().Str("address", addr).Msg("Starting proxy server")

	server := http.Server{
		Addr:              addr,
		Handler:           &proxy{blockHttp: blockHttp, version: versionAndDevice},
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutCtx)
	}()

	var failed atomic.Bool
	go func() {
		// wait for server start
		time.Sleep(1 * time.Second)
		if failed.Load() {
			return
		}

		report(State{
			Type:  "ready",
			State: "Ready",
		})
	}()

	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}

	if err != nil {
		failed.Store(true)
		if strings.Contains(err.Error(), "address already in use") {
			err = fmt.Errorf("cannot start server, port %s is already in use by another application", addr)
		}

		log.Error().Err(err).Msg("Failed to init proxy server")

		text := "Failed, check logs"
		if strings.Contains(err.Error(), "address already in use") {
			text = "Port is already in use"
		}

		report(State{
			Type:    "error",
			State:   text,
			Stopped: true,
		})
	}

	return err
}

func initDNSResolver(cfg *liteclient.GlobalConfig) (*liteclient.ConnectionPool, *dns.Client, error) {
	pool := liteclient.NewConnectionPool()

	err := pool.AddConnectionsFromConfig(context.Background(), cfg)
	if err != nil {
		return nil, nil, err
	}

	// initialize ton api lite connection wrapper
	api := ton.NewAPIClient(pool)

	var root *address.Address
	for i := 0; i < 5; i++ { // retry to not get liteserver not found block err
		// get root dns address from network config
		root, err = dns.GetRootContractAddr(context.Background(), api)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		break
	}
	if err != nil {
		return nil, nil, err
	}

	return pool, dns.NewDNSClient(api, root), nil
}

