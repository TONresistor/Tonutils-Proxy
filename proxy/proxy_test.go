package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xssnick/tonutils-proxy/resolver"
)

type contenthashResolver struct {
	raw []byte
}

func (r *contenthashResolver) Resolve(string) (string, error) {
	return "", fmt.Errorf("unexpected legacy ADNL resolution")
}

func (r *contenthashResolver) ResolveSite(string) (resolver.SiteTarget, error) {
	target, ok, err := resolver.ExtractSiteFromContenthash(r.raw)
	if err == nil && !ok {
		err = fmt.Errorf("unsupported contenthash")
	}
	return target, err
}

func (r *contenthashResolver) Close() {}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestENSContenthashRouting(t *testing.T) {
	const idHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	id, err := resolver.ParseADNLAddress(idHex)
	if err != nil {
		t.Fatal(err)
	}
	adnl, err := resolver.SerializeADNLAddress(id[:])
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		host string
	}{
		{name: "ADNL", raw: resolver.EncodeContenthash(resolver.MulticodecADNL, id[:]), host: adnl + ".adnl"},
		{name: "storage", raw: resolver.EncodeContenthash(resolver.MulticodecTONStorage, id[:]), host: idHex + ".bag"},
		{name: "malformed storage", raw: resolver.EncodeContenthash(resolver.MulticodecTONStorage, id[:31])},
		{name: "unsupported codec", raw: resolver.EncodeContenthash(0xe3, id[:])},
	} {
		for _, blockHTTP := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/blockHTTP=%v", tc.name, blockHTTP), func(t *testing.T) {
				multi := resolver.NewMultiResolver()
				defer multi.Close()
				multi.Register(".eth", &contenthashResolver{raw: tc.raw})
				p := &proxy{multiResolver: multi, blockHttp: blockHTTP}
				previousClient, previousDefault := client, http.DefaultClient
				t.Cleanup(func() { client, http.DefaultClient = previousClient, previousDefault })
				http.DefaultClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					t.Fatal("ENS request escaped to the HTTP transport")
					return nil, fmt.Errorf("unexpected HTTP request")
				})}
				calls := 0
				client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					if req.URL.Host != tc.host || req.Host != "site.eth:80" {
						t.Fatalf("routing host=%q, original host=%q", req.URL.Host, req.Host)
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader(req.URL.RequestURI())),
					}, nil
				})}

				for _, path := range []string{"/", "/assets/app.js?v=1"} {
					rec := httptest.NewRecorder()
					p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://site.eth:80"+path, nil))
					if tc.host == "" {
						if rec.Code != http.StatusBadGateway || calls != 0 {
							t.Fatalf("invalid contenthash: status=%d, transport calls=%d", rec.Code, calls)
						}
					} else if rec.Code != http.StatusOK || rec.Body.String() != path {
						t.Fatalf("status=%d, body=%q, want path %q", rec.Code, rec.Body.String(), path)
					}
				}
				if tc.host != "" && calls != 2 {
					t.Fatalf("TON transport calls=%d, want 2", calls)
				}
			})
		}
	}
}
