package resolver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	hnsDialTimeout    = 5 * time.Second
	hnsResolveTimeout = 10 * time.Second
	hnsADNLPrefix     = "adnl="
)

func init() {
	RegisterChain(ChainConfig{
		TLD:       ".hns",
		Name:      "Handshake",
		RecordKey: "TXT",
		// No public HSD RPC endpoints exist. Users must configure their own
		// node via RPCOverrides[".hns"] = "http://host:12037".
		DefaultRPCs: nil,
		NewResolver: func(rpcURL string) (Resolver, error) {
			return newHandshakeResolver(rpcURL)
		},
	})
}

// HandshakeResolver resolves .hns domains by querying an HSD node's
// getnameresource JSON-RPC. It reads on-chain TXT records looking for an
// entry of the form "adnl=0x<64 hex chars>".
type HandshakeResolver struct {
	rpcURL string
	client *http.Client
}

func newHandshakeResolver(rpcURL string) (*HandshakeResolver, error) {
	if rpcURL == "" {
		return nil, fmt.Errorf("no HSD RPC endpoint configured for .hns (set Resolver.RPCOverrides[\".hns\"])")
	}

	r := &HandshakeResolver{
		rpcURL: rpcURL,
		client: &http.Client{Timeout: hnsResolveTimeout},
	}

	// Verify the endpoint is reachable and speaks HSD JSON-RPC.
	if err := r.verify(); err != nil {
		return nil, fmt.Errorf("HSD RPC check failed for %s: %w", rpcURL, err)
	}
	return r, nil
}

func (r *HandshakeResolver) verify() error {
	ctx, cancel := context.WithTimeout(context.Background(), hnsDialTimeout)
	defer cancel()

	// getinfo is a cheap, universally available HSD RPC call.
	_, err := r.call(ctx, "getinfo", []any{})
	return err
}

func (r *HandshakeResolver) Resolve(domain string) (string, error) {
	name := strings.TrimSuffix(strings.ToLower(domain), ".hns")
	if name == "" {
		return "", fmt.Errorf("empty domain name")
	}
	// Only TLD-level resolution is supported. Subdomains would require the
	// TLD owner to delegate via NS records served by a centralized nameserver,
	// defeating the decentralization guarantee.
	if strings.Contains(name, ".") {
		return "", fmt.Errorf("only TLD-level names are supported on .hns (got %q)", domain)
	}

	ctx, cancel := context.WithTimeout(context.Background(), hnsResolveTimeout)
	defer cancel()

	result, err := r.call(ctx, "getnameresource", []any{name})
	if err != nil {
		return "", fmt.Errorf("getnameresource %q: %w", domain, err)
	}
	if len(result) == 0 || bytes.Equal(result, []byte("null")) {
		return "", fmt.Errorf("no resource set for %q", domain)
	}

	var res hnsResource
	if err := json.Unmarshal(result, &res); err != nil {
		return "", fmt.Errorf("decode resource for %q: %w", domain, err)
	}

	adnl, err := extractADNLFromHNSRecords(res.Records)
	if err != nil {
		return "", fmt.Errorf("%w for %q", err, domain)
	}

	if _, err := ParseADNLAddress(adnl); err != nil {
		return "", fmt.Errorf("invalid ADNL record for %q: %w", domain, err)
	}
	return adnl, nil
}

func (r *HandshakeResolver) Close() {
	// http.Client has no explicit close.
}

// hnsResource matches the JSON returned by HSD's getnameresource RPC.
// Record shape varies slightly across HSD versions: TXT strings may live
// under "txt" or "text". We accept both.
type hnsResource struct {
	Records []hnsRecord `json:"records"`
}

type hnsRecord struct {
	Type string   `json:"type"`
	Txt  []string `json:"txt,omitempty"`
	Text []string `json:"text,omitempty"`
}

// extractADNLFromHNSRecords scans TXT records for an "adnl=" entry and
// returns the hex payload.
func extractADNLFromHNSRecords(records []hnsRecord) (string, error) {
	for _, rec := range records {
		if !strings.EqualFold(rec.Type, "TXT") {
			continue
		}
		strs := rec.Txt
		if len(strs) == 0 {
			strs = rec.Text
		}
		for _, s := range strs {
			s = strings.TrimSpace(s)
			if !strings.HasPrefix(strings.ToLower(s), hnsADNLPrefix) {
				continue
			}
			val := strings.TrimSpace(s[len(hnsADNLPrefix):])
			val = strings.TrimPrefix(val, "0x")
			val = strings.TrimPrefix(val, "0X")
			if val != "" {
				return val, nil
			}
		}
	}
	return "", fmt.Errorf("no ADNL TXT record")
}

// JSON-RPC 2.0 request/response against the HSD HTTP endpoint.
type hnsRPCRequest struct {
	Method string `json:"method"`
	Params []any  `json:"params"`
	ID     int    `json:"id"`
}

type hnsRPCResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *hnsRPCError    `json:"error"`
	ID     int             `json:"id"`
}

type hnsRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *hnsRPCError) Error() string {
	return fmt.Sprintf("hsd rpc error %d: %s", e.Code, e.Message)
}

// call sends a JSON-RPC request to the HSD node. The API key, if any, is
// carried in rpcURL as basic-auth credentials (user may be empty, password
// holds the API key — this is HSD's standard convention).
func (r *HandshakeResolver) call(ctx context.Context, method string, params []any) (json.RawMessage, error) {
	body, err := json.Marshal(hnsRPCRequest{Method: method, Params: params, ID: 1})
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.rpcURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("unauthorized (set API key in RPC URL as http://x:apikey@host:port)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}

	var rpcResp hnsRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, rpcResp.Error
	}
	return rpcResp.Result, nil
}
