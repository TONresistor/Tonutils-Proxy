package resolver

import (
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sigurn/crc16"
)

const (
	resolveCacheTTL = 5 * time.Minute
)

const (
	ADNLAddressSize    = 32
	adnlAddressHexLen  = ADNLAddressSize * 2
	adnlSerializePrefix = 0x2d
	adnlDomainSuffix   = ".adnl"
	ADNLRecordKey      = "adnl"
)

// Resolver resolves a domain name to a 32-byte ADNL address hex string.
type Resolver interface {
	Resolve(domain string) (string, error)
	Close()
}

// ChainConfig describes a blockchain name service that can be resolved.
type ChainConfig struct {
	TLD         string
	Name        string
	DefaultRPCs []string
	RecordKey   string
	NewResolver func(rpcURL string) (Resolver, error)
}

var registry []ChainConfig

var crc16table = crc16.MakeTable(crc16.CRC16_XMODEM)

func RegisterChain(cfg ChainConfig) {
	registry = append(registry, cfg)
}

func AllChains() []ChainConfig {
	result := make([]ChainConfig, len(registry))
	copy(result, registry)
	return result
}

type cacheEntry struct {
	adnlHost  string
	expiresAt time.Time
}

const maxCacheEntries = 10000

// MultiResolver routes resolution to chain-specific resolvers based on TLD.
type MultiResolver struct {
	resolvers  map[string]Resolver
	cacheMu    sync.RWMutex
	cacheMap   map[string]cacheEntry
	done       chan struct{}
	closeOnce  sync.Once
}

func NewMultiResolver() *MultiResolver {
	m := &MultiResolver{
		resolvers: make(map[string]Resolver),
		cacheMap:  make(map[string]cacheEntry),
		done:      make(chan struct{}),
	}
	go m.cleanupLoop()
	return m
}

func (m *MultiResolver) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			m.cacheMu.Lock()
			for k, v := range m.cacheMap {
				if now.After(v.expiresAt) {
					delete(m.cacheMap, k)
				}
			}
			m.cacheMu.Unlock()
		case <-m.done:
			return
		}
	}
}

func (m *MultiResolver) evictIfNeeded() {
	if len(m.cacheMap) <= maxCacheEntries {
		return
	}
	now := time.Now()
	for k, v := range m.cacheMap {
		if now.After(v.expiresAt) {
			delete(m.cacheMap, k)
		}
	}
	if len(m.cacheMap) <= maxCacheEntries {
		return
	}
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, v := range m.cacheMap {
		if first || v.expiresAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.expiresAt
			first = false
		}
	}
	if oldestKey != "" {
		delete(m.cacheMap, oldestKey)
	}
}

func (m *MultiResolver) Register(tld string, r Resolver) {
	m.resolvers[tld] = r
}

func (m *MultiResolver) Resolve(domain string) (string, error) {
	for tld, r := range m.resolvers {
		if strings.HasSuffix(domain, tld) {
			return r.Resolve(domain)
		}
	}
	return "", fmt.Errorf("no resolver for domain: %s", domain)
}

func (m *MultiResolver) Supports(domain string) bool {
	for tld := range m.resolvers {
		if strings.HasSuffix(domain, tld) {
			return true
		}
	}
	return false
}

func (m *MultiResolver) EnabledTLDs() []string {
	var tlds []string
	for tld := range m.resolvers {
		tlds = append(tlds, tld)
	}
	return tlds
}

func (m *MultiResolver) Close() {
	m.closeOnce.Do(func() {
		close(m.done)
		for _, r := range m.resolvers {
			r.Close()
		}
	})
}

// InitAll initializes all registered chain resolvers in parallel.
func InitAll(rpcOverrides map[string]string, disabled map[string]bool) (*MultiResolver, []string) {
	multi := NewMultiResolver()

	if rpcOverrides == nil {
		rpcOverrides = make(map[string]string)
	}
	if disabled == nil {
		disabled = make(map[string]bool)
	}

	type result struct {
		tld     string
		r       Resolver
		warning string
	}

	var active []ChainConfig
	for _, cfg := range registry {
		if !disabled[cfg.TLD] {
			active = append(active, cfg)
		}
	}

	results := make(chan result, len(active))
	for _, cfg := range active {
		go func(c ChainConfig) {
			rpc := rpcOverrides[c.TLD]
			r, err := c.NewResolver(rpc)
			if err != nil {
				results <- result{tld: c.TLD, warning: fmt.Sprintf("%s (%s): %v", c.Name, c.TLD, err)}
				return
			}
			results <- result{tld: c.TLD, r: r}
		}(cfg)
	}

	var warnings []string
	for range active {
		res := <-results
		if res.warning != "" {
			warnings = append(warnings, res.warning)
			continue
		}
		multi.Register(res.tld, res.r)
	}

	return multi, warnings
}

// SerializeADNLAddress converts a raw 32-byte ADNL address to the base32 format
// used by tonutils (.adnl domains).
func SerializeADNLAddress(addr []byte) (string, error) {
	if len(addr) != ADNLAddressSize {
		return "", fmt.Errorf("invalid address length: expected %d, got %d", ADNLAddressSize, len(addr))
	}
	a := append([]byte{adnlSerializePrefix}, addr...)
	crcBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(crcBytes, crc16.Checksum(a, crc16table))
	return strings.ToLower(base32.StdEncoding.EncodeToString(append(a, crcBytes...))[1:]), nil
}

// ResolveToADNL resolves a multi-chain domain to a routable ".adnl" hostname.
func (m *MultiResolver) ResolveToADNL(domain string) (string, error) {
	m.cacheMu.RLock()
	entry, ok := m.cacheMap[domain]
	m.cacheMu.RUnlock()
	if ok {
		if time.Now().Before(entry.expiresAt) {
			return entry.adnlHost, nil
		}
		m.cacheMu.Lock()
		if e, still := m.cacheMap[domain]; still && time.Now().After(e.expiresAt) {
			delete(m.cacheMap, domain)
		}
		m.cacheMu.Unlock()
	}

	rawHex, err := m.Resolve(domain)
	if err != nil {
		return "", err
	}

	rawHex = strings.TrimPrefix(strings.TrimPrefix(rawHex, "0x"), "0X")
	adnlBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		return "", fmt.Errorf("invalid ADNL hex for %s: %w", domain, err)
	}
	if len(adnlBytes) != ADNLAddressSize {
		return "", fmt.Errorf("invalid ADNL address for %s: expected %d bytes, got %d", domain, ADNLAddressSize, len(adnlBytes))
	}

	b32, err := SerializeADNLAddress(adnlBytes)
	if err != nil {
		return "", fmt.Errorf("encode ADNL address for %s: %w", domain, err)
	}

	adnlHost := b32 + adnlDomainSuffix
	m.cacheMu.Lock()
	m.evictIfNeeded()
	m.cacheMap[domain] = cacheEntry{
		adnlHost:  adnlHost,
		expiresAt: time.Now().Add(resolveCacheTTL),
	}
	m.cacheMu.Unlock()

	return adnlHost, nil
}

// ParseADNLAddress parses a hex string into a 32-byte ADNL address.
func ParseADNLAddress(hexStr string) ([ADNLAddressSize]byte, error) {
	var addr [ADNLAddressSize]byte
	hexStr = strings.TrimPrefix(hexStr, "0x")
	hexStr = strings.TrimPrefix(hexStr, "0X")

	if len(hexStr) != adnlAddressHexLen {
		return addr, fmt.Errorf("invalid ADNL address length: expected %d hex chars, got %d", adnlAddressHexLen, len(hexStr))
	}

	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return addr, fmt.Errorf("invalid ADNL hex: %w", err)
	}

	copy(addr[:], b)
	return addr, nil
}
