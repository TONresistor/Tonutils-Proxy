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
			"https://eth.drpc.org",
			"https://ethereum-rpc.publicnode.com",
			"https://cloudflare-eth.com",
			"https://1rpc.io/eth",
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

		adnlAddr, err := resolver.Text(ADNLRecordKey)
		if err != nil {
			ch <- result{"", fmt.Errorf("read ADNL record for %q: %w", domain, err)}
			return
		}

		if adnlAddr == "" {
			ch <- result{"", fmt.Errorf("no ADNL record set for %q", domain)}
			return
		}

		if _, err := ParseADNLAddress(adnlAddr); err != nil {
			ch <- result{"", fmt.Errorf("invalid ADNL record for %q: %w", domain, err)}
			return
		}

		ch <- result{adnlAddr, nil}
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
