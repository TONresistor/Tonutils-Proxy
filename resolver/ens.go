package resolver

import (
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	ens "github.com/wealdtech/go-ens/v3"
)

func init() {
	RegisterChain(ChainConfig{
		TLD:       ".eth",
		Name:      "Ethereum ENS",
		RecordKey: ADNLRecordKey,
		DefaultRPCs: []string{
			"https://ethereum-rpc.publicnode.com",
			"https://cloudflare-eth.com",
			"https://1rpc.io/eth",
			"https://eth.drpc.org",
		},
		NewResolver: func(rpcURL string) (Resolver, error) {
			return newENSResolver(rpcURL)
		},
	})
}

type ENSResolver struct {
	client *ethclient.Client
}

func newENSResolver(rpcURL string) (*ENSResolver, error) {
	client, err := dialEVMWithFallback(rpcURL, ".eth")
	if err != nil {
		return nil, err
	}
	return &ENSResolver{client: client}, nil
}

func (r *ENSResolver) Resolve(domain string) (string, error) {
	target, err := r.ResolveSite(domain)
	if err != nil {
		return "", err
	}
	if target.Codec != MulticodecADNL {
		return "", fmt.Errorf("%q resolves to TON Storage, not ADNL", domain)
	}
	return fmt.Sprintf("%x", target.ID), nil
}

func (r *ENSResolver) ResolveSite(domain string) (SiteTarget, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type result struct {
		target SiteTarget
		err    error
	}
	ch := make(chan result, 1)

	go func() {
		normalized, err := ens.Normalize(domain)
		if err != nil {
			ch <- result{SiteTarget{}, fmt.Errorf("normalize %q: %w", domain, err)}
			return
		}

		resolver, err := ens.NewResolver(r.client, normalized)
		if err != nil {
			ch <- result{SiteTarget{}, fmt.Errorf("ENS resolver for %q: %w", domain, err)}
			return
		}

		target, err := resolveENSRecords(resolver, domain)
		ch <- result{target, err}
	}()

	select {
	case res := <-ch:
		return res.target, res.err
	case <-ctx.Done():
		return SiteTarget{}, fmt.Errorf("resolve timeout for %q", domain)
	}
}

type ensRecords interface {
	Contenthash() ([]byte, error)
	Text(string) (string, error)
}

func resolveENSRecords(records ensRecords, domain string) (SiteTarget, error) {
	if raw, err := records.Contenthash(); err == nil && len(raw) > 0 {
		if target, ok, err := ExtractSiteFromContenthash(raw); err == nil && ok {
			return target, nil
		}
	}

	// Backward-compatible fallback: legacy "adnl" text record (pre-ENSIP-7 setups).
	if raw, err := records.Text(ADNLRecordKey); err == nil && raw != "" {
		if id, err := ParseADNLAddress(raw); err == nil {
			return SiteTarget{Codec: MulticodecADNL, ID: id}, nil
		}
	}
	return SiteTarget{}, fmt.Errorf("no ADNL or TON Storage contenthash or %q text record for %q", ADNLRecordKey, domain)
}

func (r *ENSResolver) Close() {
	r.client.Close()
}
