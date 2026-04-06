package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/ton-blockchain/adnl-tunnel/tunnel"
	"github.com/xssnick/tonutils-go/tl"
)

// ConnectConfig holds configuration for the HTTP CONNECT tunnel handler.
type ConnectConfig struct {
	Enabled      bool
	AllowedPorts []int
	MaxTunnels   int
	DialTimeout  time.Duration
	IdleTimeout  time.Duration
}

// tunnelConn tracks a single clearnet TCP connection through the tunnel.
type tunnelConn struct {
	connId uint32
	events chan tl.Serializable // receives TCPConnectedPayload, TCPDataPayload, TCPCloseResponsePayload
	ctx    context.Context
	cancel func()

	// Reorder buffer for out-of-order TCPDataPayload delivery (UDP transport doesn't guarantee order)
	reorderMu   sync.Mutex
	expectedSeq uint64                        // next expected seqno, starts at 1
	pending     map[uint64]tunnel.TCPDataPayload // buffered out-of-order chunks
	lastAdvance time.Time                     // when expectedSeq last advanced
}

var (
	tunnelConns      = make(map[uint32]*tunnelConn)
	tunnelConnsMu    sync.RWMutex
	nextTunnelConnId uint32

	// activeTunnel is set when clearnet mode is active. Used to send TCP payloads.
	activeTunnel atomic.Pointer[tunnel.AtomicSwitchableRegularTunnel]
)

func dispatchTCPPayload(payload tl.Serializable) {
	log.Trace().Msgf("tcp payload dispatch: %T", payload)
	var connId uint32
	switch p := payload.(type) {
	case tunnel.TCPOutBindDonePayload:
		log.Info().Msg("TCP out bind done")
		return
	case tunnel.TCPConnectedPayload:
		connId = p.ConnId
	case tunnel.TCPDataPayload:
		connId = p.ConnId
	case tunnel.TCPCloseResponsePayload:
		connId = p.ConnId
	default:
		log.Warn().Msgf("unknown TCP payload type: %T", payload)
		return
	}

	tunnelConnsMu.RLock()
	tc := tunnelConns[connId]
	tunnelConnsMu.RUnlock()

	if tc == nil {
		log.Debug().Uint32("conn_id", connId).Msg("no tunnel conn for TCP payload, dropping")
		return
	}

	select {
	case tc.events <- payload:
	case <-tc.ctx.Done():
	}
}

func defaultBlacklist() []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"fe80::/10",
		"fc00::/7",
		"0.0.0.0/8",
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("invalid hardcoded CIDR: " + c)
		}
		nets = append(nets, n)
	}
	return nets
}

func defaultConnectPorts() map[int]bool {
	return map[int]bool{443: true, 8443: true}
}

func (p *proxy) handleCONNECT(wr http.ResponseWriter, req *http.Request) {
	if !p.connectEnabled {
		http.Error(wr, "CONNECT not supported", http.StatusMethodNotAllowed)
		return
	}

	host, portStr, err := net.SplitHostPort(req.Host)
	if err != nil {
		http.Error(wr, "invalid host", http.StatusBadRequest)
		return
	}

	// TON domains use RLDP, not CONNECT. Reject so the browser falls back to HTTP.
	lowerHost := strings.ToLower(host)
	if strings.HasSuffix(lowerHost, ".ton") || strings.HasSuffix(lowerHost, ".adnl") ||
		strings.HasSuffix(lowerHost, ".bag") || strings.HasSuffix(lowerHost, ".t.me") || lowerHost == "t.me" {
		http.Error(wr, "CONNECT not supported for TON domains", http.StatusMethodNotAllowed)
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		http.Error(wr, "invalid port", http.StatusBadRequest)
		return
	}

	if !p.connectPorts[port] {
		log.Debug().Str("host", req.Host).Int("port", port).Msg("CONNECT port not allowed")
		http.Error(wr, "port not allowed", http.StatusForbidden)
		return
	}

	// If a tunnel exit is active, route CONNECT through it
	if activeTunnel.Load() != nil {
		p.handleClearnetCONNECT(wr, req, host, port)
		return
	}

	// Resolve before blacklist check to prevent DNS rebinding
	addr, err := net.ResolveTCPAddr("tcp", req.Host)
	if err != nil {
		log.Debug().Err(err).Str("host", req.Host).Msg("CONNECT resolve failed")
		http.Error(wr, "cannot resolve host", http.StatusBadGateway)
		return
	}

	if p.isBlacklisted(addr.IP) {
		log.Debug().Str("host", host).Str("ip", addr.IP.String()).Msg("CONNECT destination blacklisted")
		http.Error(wr, "destination not allowed", http.StatusForbidden)
		return
	}

	// Acquire semaphore
	select {
	case p.connectSem <- struct{}{}:
	default:
		http.Error(wr, "too many tunnels", http.StatusServiceUnavailable)
		return
	}
	defer func() { <-p.connectSem }()

	serverConn, err := net.DialTimeout("tcp", req.Host, p.connectTimeout)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			http.Error(wr, "dial timeout", http.StatusGatewayTimeout)
		} else {
			http.Error(wr, "dial failed", http.StatusBadGateway)
		}
		log.Debug().Err(err).Str("host", req.Host).Msg("CONNECT dial failed")
		return
	}

	hj, ok := wr.(http.Hijacker)
	if !ok {
		serverConn.Close()
		http.Error(wr, "hijack not supported", http.StatusInternalServerError)
		return
	}

	clientConn, bufrw, err := hj.Hijack()
	if err != nil {
		serverConn.Close()
		log.Error().Err(err).Msg("CONNECT hijack failed")
		return
	}

	// Flush any buffered data
	if bufrw != nil {
		_ = bufrw.Flush()
	}

	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		clientConn.Close()
		serverConn.Close()
		return
	}

	log.Debug().Str("host", req.Host).Msg("CONNECT tunnel established")
	bidirectionalCopy(clientConn, serverConn, p.connectIdleTimeout)
}

func (p *proxy) handleClearnetCONNECT(wr http.ResponseWriter, req *http.Request, host string, port int) {
	// Defense-in-depth: only port 443
	if port != 443 {
		http.Error(wr, "clearnet mode only allows port 443", http.StatusForbidden)
		return
	}

	tun := activeTunnel.Load()
	if tun == nil {
		http.Error(wr, "tunnel not ready", http.StatusServiceUnavailable)
		return
	}

	// Acquire semaphore
	select {
	case p.connectSem <- struct{}{}:
	default:
		http.Error(wr, "too many tunnels", http.StatusServiceUnavailable)
		return
	}
	defer func() { <-p.connectSem }()

	connId := atomic.AddUint32(&nextTunnelConnId, 1)

	ctx, cancel := context.WithCancel(req.Context())
	tc := &tunnelConn{
		connId:      connId,
		events:      make(chan tl.Serializable, 256),
		ctx:         ctx,
		cancel:      cancel,
		expectedSeq: 1,
		pending:     make(map[uint64]tunnel.TCPDataPayload),
		lastAdvance: time.Now(),
	}

	tunnelConnsMu.Lock()
	tunnelConns[connId] = tc
	tunnelConnsMu.Unlock()

	defer func() {
		cancel()
		tunnelConnsMu.Lock()
		delete(tunnelConns, connId)
		tunnelConnsMu.Unlock()
	}()

	// Send TCPConnectPayload through the tunnel
	connectPayload := tunnel.TCPConnectPayload{
		ConnId: connId,
		Host:   []byte(host),
		Port:   uint32(port),
	}
	if err := tun.WriteTCPPayload(connectPayload); err != nil {
		log.Error().Err(err).Str("host", req.Host).Msg("clearnet CONNECT send failed")
		http.Error(wr, "tunnel send failed", http.StatusBadGateway)
		return
	}

	// Wait for TCPConnectedPayload or TCPCloseResponsePayload
	// Use a longer timeout for tunnel-mediated connections (tunnel adds latency)
	tunnelConnectTimeout := 30 * time.Second
	if p.connectTimeout > tunnelConnectTimeout {
		tunnelConnectTimeout = p.connectTimeout
	}
	connectTimeout := time.NewTimer(tunnelConnectTimeout)
	defer connectTimeout.Stop()

	select {
	case evt := <-tc.events:
		switch evt.(type) {
		case tunnel.TCPConnectedPayload:
			// good, proceed
		case tunnel.TCPCloseResponsePayload:
			http.Error(wr, "exit node refused connection", http.StatusBadGateway)
			return
		default:
			http.Error(wr, "unexpected tunnel response", http.StatusBadGateway)
			return
		}
	case <-connectTimeout.C:
		http.Error(wr, "tunnel connect timeout", http.StatusGatewayTimeout)
		return
	case <-ctx.Done():
		return
	}

	// Hijack the HTTP connection
	hj, ok := wr.(http.Hijacker)
	if !ok {
		http.Error(wr, "hijack not supported", http.StatusInternalServerError)
		return
	}

	clientConn, bufrw, err := hj.Hijack()
	if err != nil {
		log.Error().Err(err).Msg("clearnet CONNECT hijack failed")
		return
	}
	if bufrw != nil {
		_ = bufrw.Flush()
	}

	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		clientConn.Close()
		return
	}

	log.Debug().Str("host", req.Host).Uint32("conn_id", connId).Msg("clearnet CONNECT tunnel established")

	// Bidirectional streaming: client <-> tunnel
	var wg sync.WaitGroup
	wg.Add(2)

	// Drain any bytes buffered by the HTTP server's bufio.Reader before the hijack.
	// Without this, the TLS ClientHello can be split across the bufio buffer and the raw conn,
	// causing "wrong version number" errors on the remote server.
	if bufrw != nil && bufrw.Reader.Buffered() > 0 {
		buffered := make([]byte, bufrw.Reader.Buffered())
		n, _ := bufrw.Read(buffered)
		if n > 0 {
			_ = tun.WriteTCPPayload(tunnel.TCPDataPayload{ConnId: connId, Data: buffered[:n]})
		}
	}

	// Client -> tunnel
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			_ = clientConn.SetReadDeadline(time.Now().Add(p.connectIdleTimeout))
			n, readErr := clientConn.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				sendErr := tun.WriteTCPPayload(tunnel.TCPDataPayload{
					ConnId: connId,
					Data:   data,
				})
				if sendErr != nil {
					log.Debug().Err(sendErr).Uint32("conn_id", connId).Msg("clearnet send data failed")
					break
				}
			}
			if readErr != nil {
				// Send FIN
				_ = tun.WriteTCPPayload(tunnel.TCPDataPayload{
					ConnId: connId,
					Fin:    true,
				})
				break
			}
		}
	}()

	// Tunnel -> client (with reorder buffer for out-of-order UDP delivery)
	go func() {
		defer wg.Done()

		// writeOrdered drains consecutive chunks from the reorder buffer and writes to client
		writeOrdered := func() (fin bool, err error) {
			for {
				chunk, ok := tc.pending[tc.expectedSeq]
				if !ok {
					return false, nil
				}
				delete(tc.pending, tc.expectedSeq)
				tc.expectedSeq++
				tc.lastAdvance = time.Now()

				if chunk.Fin {
					if tcpConn, ok := clientConn.(*net.TCPConn); ok {
						_ = tcpConn.CloseWrite()
					}
					return true, nil
				}
				if _, writeErr := clientConn.Write(chunk.Data); writeErr != nil {
					return false, writeErr
				}
			}
		}

		staleCheck := time.NewTicker(5 * time.Second)
		defer staleCheck.Stop()

		for {
			select {
			case evt, ok := <-tc.events:
				if !ok {
					return
				}
				switch p := evt.(type) {
				case tunnel.TCPDataPayload:
					tc.reorderMu.Lock()
					if p.Seqno < tc.expectedSeq {
						// Duplicate, drop
						tc.reorderMu.Unlock()
						continue
					}
					if len(tc.pending) > 256 {
						tc.reorderMu.Unlock()
						log.Warn().Uint32("conn_id", connId).Msg("reorder buffer overflow")
						return
					}
					tc.pending[p.Seqno] = p
					fin, err := writeOrdered()
					tc.reorderMu.Unlock()
					if fin || err != nil {
						return
					}
				case tunnel.TCPCloseResponsePayload:
					log.Debug().Uint32("conn_id", connId).Uint32("reason", p.Reason).Msg("clearnet connection closed by exit node")
					return
				}
			case <-staleCheck.C:
				tc.reorderMu.Lock()
				if len(tc.pending) > 0 && time.Since(tc.lastAdvance) > 30*time.Second {
					tc.reorderMu.Unlock()
					log.Warn().Uint32("conn_id", connId).Uint64("expected", tc.expectedSeq).
						Int("buffered", len(tc.pending)).Msg("reorder gap timeout")
					return
				}
				tc.reorderMu.Unlock()
			case <-tc.ctx.Done():
				return
			}
		}
	}()

	wg.Wait()
	clientConn.Close()

	// Tell exit node we're done
	_ = tun.WriteTCPPayload(tunnel.TCPClosePayload{ConnId: connId})
}

func (p *proxy) isBlacklisted(ip net.IP) bool {
	for _, cidr := range p.connectBlacklist {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func bidirectionalCopy(client, server net.Conn, idleTimeout time.Duration) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyDir := func(dst, src net.Conn) {
		defer wg.Done()
		_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
		_, _ = io.Copy(dst, src)
		// Close write half if possible
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}

	go copyDir(server, client)
	go copyDir(client, server)

	wg.Wait()
	client.Close()
	server.Close()
}
