package resolver

import (
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	evmDialTimeout = 5 * time.Second
)

var evmChainIDs = map[string]int64{
	".eth": 1,
	".bnb": 56,
}

func dialAndVerifyEVM(rpcURL string, expectedChainID ...int64) (*ethclient.Client, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", rpcURL, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), evmDialTimeout)
	defer cancel()

	chainID, err := client.ChainID(ctx)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("RPC check failed for %s: %w", rpcURL, err)
	}

	if len(expectedChainID) > 0 && chainID.Int64() != expectedChainID[0] {
		client.Close()
		return nil, fmt.Errorf("chain ID mismatch for %s: expected %d, got %d", rpcURL, expectedChainID[0], chainID.Int64())
	}

	return client, nil
}

func dialEVMWithFallback(rpcURL string, tld string) (*ethclient.Client, error) {
	expected := evmChainIDs[tld]
	if rpcURL != "" {
		return dialAndVerifyEVM(rpcURL, expected)
	}

	cfg := findChainConfig(tld)
	if len(cfg.DefaultRPCs) == 0 {
		return nil, fmt.Errorf("no RPC endpoints configured for %s", tld)
	}

	var lastErr error
	for _, url := range cfg.DefaultRPCs {
		c, err := dialAndVerifyEVM(url, expected)
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("no working RPC found for %s: %w", tld, lastErr)
}

func findChainConfig(tld string) ChainConfig {
	for _, cfg := range registry {
		if cfg.TLD == tld {
			return cfg
		}
	}
	return ChainConfig{}
}
