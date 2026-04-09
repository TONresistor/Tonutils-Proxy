package resolver

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newMockHSD creates a fake HSD JSON-RPC server. handler returns the value
// for getnameresource; getinfo is always stubbed to succeed.
func newMockHSD(t *testing.T, handler func(name string) (any, error)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req hnsRPCRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := hnsRPCResponse{ID: req.ID}
		switch req.Method {
		case "getinfo":
			resp.Result = json.RawMessage(`{"version":"6.0.0"}`)
		case "getnameresource":
			if len(req.Params) == 0 {
				resp.Error = &hnsRPCError{Code: -1, Message: "missing name"}
				break
			}
			name, _ := req.Params[0].(string)
			val, err := handler(name)
			if err != nil {
				resp.Error = &hnsRPCError{Code: -2, Message: err.Error()}
				break
			}
			raw, _ := json.Marshal(val)
			resp.Result = raw
		default:
			resp.Error = &hnsRPCError{Code: -3, Message: "unknown method"}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestHandshakeResolver_Success(t *testing.T) {
	srv := newMockHSD(t, func(name string) (any, error) {
		if name != "tonnet" {
			return nil, nil
		}
		return map[string]any{
			"records": []map[string]any{
				{"type": "TXT", "txt": []string{"adnl=0x" + testADNLHex}},
			},
		}, nil
	})
	defer srv.Close()

	r, err := newHandshakeResolver(srv.URL)
	if err != nil {
		t.Fatalf("newHandshakeResolver: %v", err)
	}
	defer r.Close()

	got, err := r.Resolve("tonnet.hns")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != testADNLHex {
		t.Errorf("expected %q, got %q", testADNLHex, got)
	}
}

func TestHandshakeResolver_TextFieldFallback(t *testing.T) {
	// Older HSD versions serialize TXT strings under "text" instead of "txt".
	srv := newMockHSD(t, func(name string) (any, error) {
		return map[string]any{
			"records": []map[string]any{
				{"type": "TXT", "text": []string{"adnl=" + testADNLHex}},
			},
		}, nil
	})
	defer srv.Close()

	r, _ := newHandshakeResolver(srv.URL)
	defer r.Close()

	got, err := r.Resolve("tonnet.hns")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != testADNLHex {
		t.Errorf("expected %q, got %q", testADNLHex, got)
	}
}

func TestHandshakeResolver_MultipleTXT(t *testing.T) {
	// Resolver must skip unrelated TXT records and find the ADNL one.
	srv := newMockHSD(t, func(name string) (any, error) {
		return map[string]any{
			"records": []map[string]any{
				{"type": "TXT", "txt": []string{"unrelated=value"}},
				{"type": "NS", "ns": "ns1.example."},
				{"type": "TXT", "txt": []string{"adnl=" + testADNLHex}},
			},
		}, nil
	})
	defer srv.Close()

	r, _ := newHandshakeResolver(srv.URL)
	defer r.Close()

	got, err := r.Resolve("tonnet.hns")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != testADNLHex {
		t.Errorf("expected %q, got %q", testADNLHex, got)
	}
}

func TestHandshakeResolver_NoADNLRecord(t *testing.T) {
	srv := newMockHSD(t, func(name string) (any, error) {
		return map[string]any{
			"records": []map[string]any{
				{"type": "TXT", "txt": []string{"profile email=hello@example.com"}},
			},
		}, nil
	})
	defer srv.Close()

	r, _ := newHandshakeResolver(srv.URL)
	defer r.Close()

	_, err := r.Resolve("tonnet.hns")
	if err == nil || !strings.Contains(err.Error(), "no ADNL") {
		t.Errorf("expected 'no ADNL' error, got: %v", err)
	}
}

func TestHandshakeResolver_NullResource(t *testing.T) {
	srv := newMockHSD(t, func(name string) (any, error) {
		return nil, nil
	})
	defer srv.Close()

	r, _ := newHandshakeResolver(srv.URL)
	defer r.Close()

	_, err := r.Resolve("tonnet.hns")
	if err == nil || !strings.Contains(err.Error(), "no resource") {
		t.Errorf("expected 'no resource' error, got: %v", err)
	}
}

func TestHandshakeResolver_InvalidADNLHex(t *testing.T) {
	srv := newMockHSD(t, func(name string) (any, error) {
		return map[string]any{
			"records": []map[string]any{
				{"type": "TXT", "txt": []string{"adnl=deadbeef"}},
			},
		}, nil
	})
	defer srv.Close()

	r, _ := newHandshakeResolver(srv.URL)
	defer r.Close()

	_, err := r.Resolve("tonnet.hns")
	if err == nil || !strings.Contains(err.Error(), "invalid ADNL") {
		t.Errorf("expected 'invalid ADNL' error, got: %v", err)
	}
}

func TestHandshakeResolver_SubdomainRejected(t *testing.T) {
	// Subdomains are not supported — they would require NS delegation to a
	// centralized nameserver, breaking the decentralization guarantee.
	srv := newMockHSD(t, func(name string) (any, error) {
		t.Errorf("RPC should not be called for subdomains")
		return nil, nil
	})
	defer srv.Close()

	r, _ := newHandshakeResolver(srv.URL)
	defer r.Close()

	_, err := r.Resolve("blog.tonnet.hns")
	if err == nil || !strings.Contains(err.Error(), "TLD-level") {
		t.Errorf("expected 'TLD-level' error, got: %v", err)
	}
}

func TestHandshakeResolver_EmptyRPCURL(t *testing.T) {
	_, err := newHandshakeResolver("")
	if err == nil || !strings.Contains(err.Error(), "no HSD RPC") {
		t.Errorf("expected 'no HSD RPC' error, got: %v", err)
	}
}

func TestHandshakeResolver_RPCError(t *testing.T) {
	srv := newMockHSD(t, func(name string) (any, error) {
		return nil, io.EOF
	})
	defer srv.Close()

	r, _ := newHandshakeResolver(srv.URL)
	defer r.Close()

	_, err := r.Resolve("tonnet.hns")
	if err == nil || !strings.Contains(err.Error(), "hsd rpc error") {
		t.Errorf("expected hsd rpc error, got: %v", err)
	}
}

func TestExtractADNLFromHNSRecords_CaseInsensitivePrefix(t *testing.T) {
	records := []hnsRecord{
		{Type: "txt", Txt: []string{"ADNL=" + testADNLHex}},
	}
	got, err := extractADNLFromHNSRecords(records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testADNLHex {
		t.Errorf("expected %q, got %q", testADNLHex, got)
	}
}

func TestHandshakeResolver_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := newHandshakeResolver(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("expected 'unauthorized' error, got: %v", err)
	}
}
