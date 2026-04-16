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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type result struct {
		addr string
		err  error
	}
	ch := make(chan result, 1)

	go func() {
		normalized, err := ens.Normalize(domain)
		if err != nil {
			ch <- result{"", fmt.Errorf("normalize %q: %w", domain, err)}
			return
		}

		resolver, err := ens.NewResolver(r.client, normalized)
		if err != nil {
			ch <- result{"", fmt.Errorf("ENS resolver for %q: %w", domain, err)}
			return
		}

		// ENSIP-7 contenthash (standard approach)
		raw, chErr := resolver.Contenthash()
		if chErr != nil {
			ch <- result{"", fmt.Errorf("read contenthash for %q: %w", domain, chErr)}
			return
		}

		if len(raw) == 0 {
			ch <- result{"", fmt.Errorf("no contenthash set for %q", domain)}
			return
		}

		hexAdnl, ok, extractErr := ExtractADNLFromContenthash(raw)
		if extractErr != nil {
			ch <- result{"", fmt.Errorf("parse contenthash for %q: %w", domain, extractErr)}
			return
		}

		if !ok {
			ch <- result{"", fmt.Errorf("contenthash codec not supported for %q (expected adnl)", domain)}
			return
		}

		ch <- result{hexAdnl, nil}
	}()

	select {
	case res := <-ch:
		return res.addr, res.err
	case <-ctx.Done():
		return "", fmt.Errorf("resolve timeout for %q", domain)
	}
}

func (r *ENSResolver) Close() {
	r.client.Close()
}
