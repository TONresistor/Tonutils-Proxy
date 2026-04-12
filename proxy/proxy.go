package proxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	tunnelConfig "github.com/ton-blockchain/adnl-tunnel/config"
	"github.com/ton-blockchain/adnl-tunnel/tunnel"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/adnl"
	adnlAddress "github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/tl"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/dns"
	"github.com/xssnick/tonutils-proxy/proxy/transport"
	"github.com/xssnick/tonutils-proxy/resolver"
	"github.com/xssnick/tonutils-storage/config"
	"github.com/xssnick/tonutils-storage/storage"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

const (
	tunnelNodesCacheTTL       = 1 * time.Hour
	dhtDiscoverInitialBackoff = 500 * time.Millisecond
	dhtDiscoverAttemptTimeout = 8 * time.Second
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
	version       string
	blockHttp     bool
	multiResolver *resolver.MultiResolver
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

	// Resolve multi-chain domains (e.g. .eth) to .adnl before routing
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if len(host) > 253 {
		http.Error(wr, "invalid host", http.StatusBadRequest)
		return
	}
	if p.multiResolver != nil && p.multiResolver.Supports(host) {
		newHost, err := p.multiResolver.ResolveToADNL(host)
		if err != nil {
			http.Error(wr, fmt.Sprintf("Failed to resolve %s: %v", host, err), http.StatusBadGateway)
			return
		}
		log.Debug().Str("domain", host).Str("adnl", newHost).Msg("multi-chain resolved")
		req.Host = newHost
		req.URL.Host = newHost
	}

	var c = http.DefaultClient
	if strings.HasSuffix(req.Host, ".ton") || strings.HasSuffix(req.Host, ".adnl") ||
		strings.HasSuffix(req.Host, ".t.me") || strings.HasSuffix(req.Host, ".bag") {
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

// MultiChainConfig holds configuration for multi-blockchain domain resolution.
type MultiChainConfig struct {
	// RPCOverrides maps TLD (e.g. ".eth") to a custom RPC URL.
	RPCOverrides map[string]string
	// Disabled is a set of TLDs to skip (e.g. ".eth" → true).
	Disabled map[string]bool
}

func RunProxy(closerCtx context.Context, addr string, adnlKey ed25519.PrivateKey, res chan<- State, versionAndDevice string, blockHttp bool, netConfigPath string, tunCfg *tunnelConfig.ClientConfig, customTunNetCfg *liteclient.GlobalConfig, multiChainCfg *MultiChainConfig) error {
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
			if err = json.NewDecoder(bytes.NewBufferString(config.FallbackNetworkConfig)).Decode(lsCfg); err != nil {
				return fmt.Errorf("failed to parse fallback ton config: %w", err)
			}
		}
	}

	return RunProxyWithConfig(closerCtx, addr, adnlKey, res, blockHttp, versionAndDevice, lsCfg, tunCfg, customTunNetCfg, multiChainCfg)
}

var OnTunnel = func(addr string) {}
var OnPaidUpdate = func(paid tlb.Coins) {}

var OnAskAccept = func(to, from []*tunnel.SectionInfo) int {
	return tunnel.AcceptorDecisionAccept
}
var OnAskReroute = func() bool { return false }

var OnTunnelStopped = func() {}

func RunProxyWithConfig(closerCtx context.Context, addr string, adnlKey ed25519.PrivateKey, res chan<- State, blockHttp bool, versionAndDevice string, lsCfg *liteclient.GlobalConfig, tunCfg *tunnelConfig.ClientConfig, customTunNetCfg *liteclient.GlobalConfig, multiChainCfg *MultiChainConfig) error {
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

	// Initialize multi-chain resolver (ENS, etc.)
	var multiRes *resolver.MultiResolver
	var warnings []string
	if multiChainCfg != nil {
		multiRes, warnings = resolver.InitAll(multiChainCfg.RPCOverrides, multiChainCfg.Disabled)
	} else {
		multiRes, warnings = resolver.InitAll(nil, nil)
	}
	for _, w := range warnings {
		log.Warn().Str("warning", w).Msg("chain resolver init failed")
	}
	if tlds := multiRes.EnabledTLDs(); len(tlds) > 0 {
		log.Info().Strs("tlds", tlds).Msg("Multi-chain resolver initialized")
	} else {
		log.Warn().Msg("No multi-chain resolvers available, only TON domains will work")
	}
	defer multiRes.Close()

	var gate *adnl.Gateway
	var netMgr adnl.NetManager
	if tunCfg != nil && tunCfg.TunnelSectionsNum >= 2 {
		report(State{
			Type:  "loading",
			State: "Preparing ADNL tunnel...",
		})

		var tunNodesCfg tunnelConfig.SharedConfig

		if tunCfg.NodesPoolConfigPath != "" {
			info, statErr := os.Stat(tunCfg.NodesPoolConfigPath)
			switch {
			case statErr != nil && !os.IsNotExist(statErr):
				log.Warn().Err(statErr).Msg("Failed to stat tunnel nodes cache, falling back to DHT discovery")
			case statErr == nil && time.Since(info.ModTime()) > tunnelNodesCacheTTL:
				log.Info().Msg("Tunnel nodes cache too old, refreshing via DHT")
			case statErr == nil:
				data, err := os.ReadFile(tunCfg.NodesPoolConfigPath)
				if err != nil {
					log.Warn().Err(err).Msg("Failed to load tunnel nodes pool file, falling back to DHT discovery")
				} else if err = json.Unmarshal(data, &tunNodesCfg); err != nil {
					log.Warn().Err(err).Msg("Failed to parse tunnel nodes pool file, falling back to DHT discovery")
				}
			}
		}

		// If pool is empty, discover tunnel relays from DHT
		if len(tunNodesCfg.NodesPool) == 0 {
			log.Info().Msg("Discovering tunnel relay nodes from DHT...")
			discovered := discoverTunnelNodes(lsCfg)
			if len(discovered) == 0 {
				return fmt.Errorf("no tunnel relay nodes found via DHT")
			}
			tunNodesCfg.NodesPool = discovered
			log.Info().Int("count", len(discovered)).Msg("Tunnel relay nodes discovered from DHT")
			if tunCfg.NodesPoolConfigPath != "" {
				if err := tunnelConfig.SaveConfig(&tunNodesCfg, tunCfg.NodesPoolConfigPath); err != nil {
					log.Warn().Err(err).Msg("Failed to persist tunnel nodes cache")
				} else {
					log.Info().Str("path", tunCfg.NodesPoolConfigPath).Msg("Persisted tunnel nodes for warm restart")
				}
			}
		}

		if customTunNetCfg == nil {
			customTunNetCfg = lsCfg
		}

		tunnel.ChannelPacketsToPrepay = 30000
		tunnel.ChannelCapacityForNumPayments = 50

		tunnel.AskReroute = OnAskReroute
		tunnel.Acceptor = OnAskAccept
		events := make(chan any, 1)
		go tunnel.RunTunnel(ctx, tunCfg, &tunNodesCfg, customTunNetCfg, log.Logger, events)

		initUpd := make(chan any, 1)
		inited := false
		go func() {
			atm := &tunnel.AtomicSwitchableRegularTunnel{}
			for event := range events {
				switch e := event.(type) {
				case tunnel.StoppedEvent:
					OnTunnelStopped()
					return
				case tunnel.MsgEvent:
					if !inited {
						report(State{
							Type:  "loading",
							State: e.Msg,
						})
					}
				case tunnel.UpdatedEvent:
					log.Info().Msg("tunnel updated")

					e.Tunnel.SetOutAddressChangedHandler(func(addr *net.UDPAddr) {
						gate.SetAddressList([]*adnlAddress.UDP{
							{
								IP:   addr.IP,
								Port: int32(addr.Port),
							},
						})
						OnTunnel(addr.String())
					})
					OnTunnel(fmt.Sprintf("%s:%d", e.ExtIP.String(), e.ExtPort))

					go func() {
						for {
							select {
							case <-e.Tunnel.AliveCtx().Done():
								return
							case <-time.After(5 * time.Second):
								OnPaidUpdate(e.Tunnel.CalcPaidAmount()["TON"])
							}
						}
					}()

					atm.SwitchTo(e.Tunnel)
					if !inited {
						inited = true
						netMgr = adnl.NewMultiNetReader(atm)
						gate = adnl.NewGatewayWithNetManager(adnlKey, netMgr)

						select {
						case initUpd <- e:
						default:
						}
					} else {
						gate.SetAddressList([]*adnlAddress.UDP{
							{
								IP:   e.ExtIP,
								Port: int32(e.ExtPort),
							},
						})

						log.Info().Msg("connection switched to new tunnel")
					}
				case tunnel.ConfigurationErrorEvent:
					report(State{
						Type:  "loading",
						State: "Tunnel configuration error, will retry...",
					})
					log.Err(e.Err).Msg("tunnel configuration error, will retry...")
				case error:
					select {
					case initUpd <- e:
					default:
					}
				}
			}
		}()

		switch x := (<-initUpd).(type) {
		case tunnel.UpdatedEvent:
			log.Info().
				Str("ip", x.ExtIP.String()).
				Uint16("port", x.ExtPort).
				Msg("using tunnel")
		case error:
			return fmt.Errorf("tunnel preparation failed: %w", x)
		}
	} else {
		dl, err := adnl.DefaultListener(":")
		if err != nil {
			log.Error().Err(err).Msg("Failed to create default listener")
			return err
		}
		netMgr = adnl.NewMultiNetReader(dl)
		gate = adnl.NewGatewayWithNetManager(adnlKey, netMgr)
	}
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
		Handler:           &proxy{blockHttp: blockHttp, version: versionAndDevice, multiResolver: multiRes},
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

// discoverTunnelNodes creates a temporary DHT client, queries for tunnel relay
// nodes, and returns them as TunnelRouteSection entries ready for adnl-tunnel.
func discoverTunnelNodes(netCfg *liteclient.GlobalConfig) []tunnelConfig.TunnelRouteSection {
	// Create a temporary ADNL gateway + DHT client for discovery
	_, tmpKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate temp DHT key")
		return nil
	}
	tmpGate := adnl.NewGateway(tmpKey)
	if err := tmpGate.StartClient(); err != nil {
		log.Error().Err(err).Msg("Failed to start temp DHT gateway")
		return nil
	}
	defer tmpGate.Close()

	dhtClient, err := dht.NewClientFromConfig(tmpGate, netCfg)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create temp DHT client")
		return nil
	}
	defer dhtClient.Close()
	// Compute the tunnel overlay key: tl.Hash(OverlayKey{PaymentNode: [0...0]})
	// Compute the tunnel overlay key for free relay nodes
	overlayKey, err := tl.Hash(tunnel.OverlayKey{PaymentNode: make([]byte, 32)})
	if err != nil {
		log.Error().Err(err).Msg("Failed to compute tunnel overlay key")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	var allNodes []overlay.Node
	var lastErr error

	// Retry with exponential backoff (500ms, 1s, 2s). Each attempt has an 8s timeout.
	backoff := dhtDiscoverInitialBackoff
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(backoff):
				backoff *= 2
			case <-ctx.Done():
				return nil
			}
		}

		attemptCtx, attemptCancel := context.WithTimeout(ctx, dhtDiscoverAttemptTimeout)
		var cont *dht.Continuation
		for i := 0; i < 3; i++ {
			nodesList, c, err := dhtClient.FindOverlayNodes(attemptCtx, overlayKey, cont)
			if err != nil {
				lastErr = err
				break
			}
			if nodesList != nil {
				allNodes = append(allNodes, nodesList.List...)
			}
			if c == nil {
				break
			}
			cont = c
		}
		attemptCancel()

		if len(allNodes) > 0 {
			break
		}
	}

	if len(allNodes) == 0 {
		log.Warn().Err(lastErr).Msg("DHT tunnel relay discovery failed after retries")
		return nil
	}

	// Deduplicate by public key and convert to TunnelRouteSection
	seen := make(map[string]bool)
	var sections []tunnelConfig.TunnelRouteSection
	for _, node := range allNodes {
		id, ok := node.ID.(keys.PublicKeyED25519)
		if !ok {
			continue
		}
		keyHex := hex.EncodeToString(id.Key)
		if seen[keyHex] {
			continue
		}
		seen[keyHex] = true
		sections = append(sections, tunnelConfig.TunnelRouteSection{
			Key: id.Key,
		})
	}

	return sections
}
