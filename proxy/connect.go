package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/xssnick/tonutils-proxy/proxy/transport"
)

func (p *proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "CONNECT requires host:port", http.StatusBadRequest)
		return
	}
	route := host
	if p.multiResolver != nil && p.multiResolver.Supports(host) {
		route, err = p.multiResolver.ResolveToADNL(host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	}
	if !strings.HasSuffix(route, ".ton") && !strings.HasSuffix(route, ".adnl") && !strings.HasSuffix(route, ".t.me") {
		http.Error(w, "CONNECT requires a TON site", http.StatusBadRequest)
		return
	}
	tr, ok := client.Transport.(*transport.Transport)
	if !ok {
		http.Error(w, "TON transport unavailable", http.StatusServiceUnavailable)
		return
	}
	tunnel, err := tr.Connect(r.Context(), route, r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer tunnel.Close()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT requires HTTP/1", http.StatusHTTPVersionNotSupported)
		return
	}
	conn, buffer, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if _, err = fmt.Fprint(buffer, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err = buffer.Flush(); err != nil {
		return
	}
	uploaded := make(chan struct{})
	go func() {
		if _, err := io.Copy(tunnel, buffer); err != nil {
			_ = tunnel.Close()
			_ = conn.Close()
		}
		_ = tunnel.CloseWrite()
		close(uploaded)
	}()
	_, err = io.Copy(conn, tunnel)
	if err == nil {
		if tcp, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = tcp.CloseWrite()
		} else {
			_ = conn.Close()
		}
	} else {
		_ = conn.Close()
		_ = tunnel.Close()
	}
	<-uploaded
}
