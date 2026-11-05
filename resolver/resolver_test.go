package resolver

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

const testADNLHex = "b1b408ed6d2b664488336aa428d258ddce44683a730aff11d7ccf785f5e74a89"

type mockResolver struct {
	result string
	err    error
	calls  int
}

func (m *mockResolver) Resolve(domain string) (string, error) {
	m.calls++
	return m.result, m.err
}

func (m *mockResolver) Close() {}

func TestSerializeADNLAddress(t *testing.T) {
	addr := make([]byte, 32)
	for i := range addr {
		addr[i] = byte(i)
	}

	result, err := SerializeADNLAddress(addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 55 {
		t.Errorf("expected 55 chars, got %d: %q", len(result), result)
	}
	if result != strings.ToLower(result) {
		t.Errorf("expected lowercase, got: %q", result)
	}
}

func TestSerializeADNLAddress_InvalidLength(t *testing.T) {
	_, err := SerializeADNLAddress(make([]byte, 31))
	if err == nil {
		t.Error("expected error for 31 bytes")
	}

	_, err = SerializeADNLAddress(make([]byte, 33))
	if err == nil {
		t.Error("expected error for 33 bytes")
	}
}

func TestParseADNLAddress(t *testing.T) {
	addr, err := ParseADNLAddress(testADNLHex)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr == ([32]byte{}) {
		t.Error("expected non-zero address")
	}
}

func TestParseADNLAddress_WithPrefix(t *testing.T) {
	addrPlain, _ := ParseADNLAddress(testADNLHex)
	addrPrefixed, err := ParseADNLAddress("0x" + testADNLHex)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addrPlain != addrPrefixed {
		t.Error("0x prefix should produce same result")
	}
}

func TestParseADNLAddress_WrongLength(t *testing.T) {
	_, err := ParseADNLAddress(testADNLHex[:62])
	if err == nil {
		t.Error("expected error for 62 chars")
	}
}

func TestParseADNLAddress_NonHex(t *testing.T) {
	_, err := ParseADNLAddress(strings.Repeat("z", 64))
	if err == nil {
		t.Error("expected error for non-hex chars")
	}
}

func TestSerializeParseRoundTrip(t *testing.T) {
	original, err := ParseADNLAddress(testADNLHex)
	if err != nil {
		t.Fatalf("ParseADNLAddress: %v", err)
	}

	hexStr := hex.EncodeToString(original[:])
	recovered, err := ParseADNLAddress(hexStr)
	if err != nil {
		t.Fatalf("ParseADNLAddress round-trip: %v", err)
	}
	if original != recovered {
		t.Errorf("round-trip failed: got %x, want %x", recovered, original)
	}

	b32, err := SerializeADNLAddress(original[:])
	if err != nil {
		t.Fatalf("SerializeADNLAddress: %v", err)
	}
	b32_2, err := SerializeADNLAddress(recovered[:])
	if err != nil {
		t.Fatalf("SerializeADNLAddress (recovered): %v", err)
	}
	if b32 != b32_2 {
		t.Errorf("serialize inconsistent: %q vs %q", b32, b32_2)
	}
}

func TestMultiResolverSupports(t *testing.T) {
	m := NewMultiResolver()
	defer m.Close()

	mock := &mockResolver{result: testADNLHex}
	m.Register(".test", mock)

	if !m.Supports("example.test") {
		t.Error("expected Supports(example.test) true")
	}
	if m.Supports("example.foo") {
		t.Error("expected Supports(example.foo) false")
	}
}

func TestMultiResolverResolve(t *testing.T) {
	m := NewMultiResolver()
	defer m.Close()

	mock := &mockResolver{result: testADNLHex}
	m.Register(".test", mock)

	result, err := m.Resolve("example.test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != testADNLHex {
		t.Errorf("expected %q, got %q", testADNLHex, result)
	}
}

func TestResolveToADNL(t *testing.T) {
	m := NewMultiResolver()
	defer m.Close()

	mock := &mockResolver{result: testADNLHex}
	m.Register(".test", mock)

	result, err := m.ResolveToADNL("example.test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(result, ".adnl") {
		t.Errorf("expected .adnl suffix, got %q", result)
	}
}

func TestResolveToADNLCache(t *testing.T) {
	m := NewMultiResolver()
	defer m.Close()

	mock := &mockResolver{result: testADNLHex}
	m.Register(".test", mock)

	_, err := m.ResolveToADNL("example.test")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	_, err = m.ResolveToADNL("example.test")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	if mock.calls != 1 {
		t.Errorf("expected mock called once (cache hit on 2nd call), got %d calls", mock.calls)
	}
}

func TestResolveToADNLCacheExpiry(t *testing.T) {
	m := NewMultiResolver()
	defer m.Close()

	mock := &mockResolver{result: testADNLHex}
	m.Register(".test", mock)

	// Inject an expired cache entry
	m.cacheMu.Lock()
	m.cacheMap["example.test"] = cacheEntry{
		host:      "expired.adnl",
		expiresAt: time.Now().Add(-time.Minute),
	}
	m.cacheMu.Unlock()

	_, err := m.ResolveToADNL("example.test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.calls != 1 {
		t.Errorf("expected mock called once (cache expired), got %d calls", mock.calls)
	}
}

func TestResolveToADNLBadHex(t *testing.T) {
	// Invalid hex → "invalid ADNL hex" error
	m := NewMultiResolver()
	defer m.Close()
	m.Register(".test", &mockResolver{result: "notvalidhex"})

	_, err := m.ResolveToADNL("example.test")
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
	if !strings.Contains(err.Error(), "invalid ADNL hex") {
		t.Errorf("expected 'invalid ADNL hex' in error, got: %v", err)
	}

	// Too-short hex (valid but not 32 bytes) → "expected 32 bytes" error
	m2 := NewMultiResolver()
	defer m2.Close()
	m2.Register(".test", &mockResolver{result: "aabb"})

	_, err = m2.ResolveToADNL("example.test")
	if err == nil {
		t.Fatal("expected error for too-short hex")
	}
	if !strings.Contains(err.Error(), "expected 32 bytes") {
		t.Errorf("expected 'expected 32 bytes' in error, got: %v", err)
	}
}

func TestResolveToADNLErrorFromResolver(t *testing.T) {
	m := NewMultiResolver()
	defer m.Close()

	sentinel := fmt.Errorf("resolution failed")
	m.Register(".test", &mockResolver{err: sentinel})

	_, err := m.ResolveToADNL("example.test")
	if err == nil {
		t.Fatal("expected error from resolver")
	}
	if !strings.Contains(err.Error(), "resolution failed") {
		t.Errorf("expected propagated error, got: %v", err)
	}
}

type mockSiteResolver struct {
	mockResolver
	target    SiteTarget
	siteErr   error
	siteCalls int
}

func (r *mockSiteResolver) ResolveSite(string) (SiteTarget, error) {
	r.siteCalls++
	return r.target, r.siteErr
}

func TestResolveToHostStorageCache(t *testing.T) {
	m := NewMultiResolver()
	defer m.Close()
	const bagID = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	id, err := ParseADNLAddress(bagID)
	if err != nil {
		t.Fatal(err)
	}
	mock := &mockSiteResolver{target: SiteTarget{Codec: MulticodecTONStorage, ID: id}}
	m.Register(".eth", mock)

	for i := 0; i < 2; i++ {
		host, err := m.ResolveToHost("site.eth")
		if err != nil || host != bagID+".bag" {
			t.Fatalf("host = %q, err = %v", host, err)
		}
	}
	if host, err := m.ResolveToADNL("site.eth"); err == nil || host != "" {
		t.Fatalf("cached storage treated as ADNL: host=%q, err=%v", host, err)
	}
	if mock.siteCalls != 1 || mock.calls != 0 {
		t.Fatalf("typed calls = %d, legacy calls = %d", mock.siteCalls, mock.calls)
	}

	m.cacheMu.Lock()
	m.cacheMap["site.eth"] = cacheEntry{host: bagID + ".bag", expiresAt: time.Now().Add(-time.Minute)}
	m.cacheMu.Unlock()
	mock.target.Codec = MulticodecADNL
	host, err := m.ResolveToHost("site.eth")
	if err != nil || !strings.HasSuffix(host, ".adnl") || mock.siteCalls != 2 {
		t.Fatalf("expired cache did not refresh target kind: host=%q, calls=%d, err=%v", host, mock.siteCalls, err)
	}
}

func TestResolveToHostRejectsInvalidTargets(t *testing.T) {
	for _, tc := range []struct {
		name string
		mock mockSiteResolver
	}{
		{name: "unknown codec", mock: mockSiteResolver{target: SiteTarget{Codec: 0xe3}}},
		{name: "resolver error", mock: mockSiteResolver{siteErr: fmt.Errorf("resolution failed")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMultiResolver()
			defer m.Close()
			m.Register(".eth", &tc.mock)
			for i := 0; i < 2; i++ {
				if host, err := m.ResolveToHost("site.eth"); err == nil || host != "" {
					t.Fatalf("invalid target accepted: host=%q, err=%v", host, err)
				}
			}
			if tc.mock.siteCalls != 2 {
				t.Fatal("resolution error was cached")
			}
		})
	}
}
