package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestProxy(enabled bool, ports map[int]bool) *proxy {
	p := &proxy{
		connectEnabled:     enabled,
		connectPorts:       ports,
		connectBlacklist:   defaultBlacklist(),
		connectTimeout:     5 * time.Second,
		connectIdleTimeout: 30 * time.Second,
		connectSem:         make(chan struct{}, 4),
	}
	return p
}

func TestCONNECT_Disabled(t *testing.T) {
	p := newTestProxy(false, nil)

	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	req.Host = "example.com:443"
	w := httptest.NewRecorder()

	p.handleCONNECT(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestCONNECT_PortNotAllowed(t *testing.T) {
	p := newTestProxy(true, map[int]bool{443: true})

	req := httptest.NewRequest("CONNECT", "example.com:22", nil)
	req.Host = "example.com:22"
	w := httptest.NewRecorder()

	p.handleCONNECT(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestCONNECT_BlacklistedIP(t *testing.T) {
	p := newTestProxy(true, map[int]bool{443: true})

	req := httptest.NewRequest("CONNECT", "127.0.0.1:443", nil)
	req.Host = "127.0.0.1:443"
	w := httptest.NewRecorder()

	p.handleCONNECT(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestCONNECT_InvalidHost(t *testing.T) {
	p := newTestProxy(true, map[int]bool{443: true})

	req := httptest.NewRequest("CONNECT", "example.com", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()

	p.handleCONNECT(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestIsBlacklisted(t *testing.T) {
	p := newTestProxy(true, nil)

	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.0.1", true},
		{"0.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"::1", true},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		got := p.isBlacklisted(ip)
		if got != tt.want {
			t.Errorf("isBlacklisted(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestDefaultConnectPorts(t *testing.T) {
	ports := defaultConnectPorts()
	if !ports[443] {
		t.Error("443 should be allowed")
	}
	if !ports[8443] {
		t.Error("8443 should be allowed")
	}
	if ports[80] {
		t.Error("80 should not be allowed")
	}
}
