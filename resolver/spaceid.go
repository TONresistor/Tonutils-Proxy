//go:build spaceid

package resolver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	ens "github.com/wealdtech/go-ens/v3"
)

type spaceIDChain struct {
	TLD         string
	Name        string
	Registry    string
	DefaultRPCs []string
}

var spaceIDChains = []spaceIDChain{
	{
		TLD:      ".bnb",
		Name:     "Space ID (.bnb)",
		Registry: "0x08ced32a7f3eec915ba84415e9c07a7286977956",
		DefaultRPCs: []string{
			"https://bsc-dataseed.binance.org",
			"https://bsc-rpc.publicnode.com",
		},
	},
}

var sidTextABI abi.ABI
var sidRegistryABI abi.ABI

func init() {
	parsed, err := abi.JSON(strings.NewReader(`[{
		"inputs": [
			{"name": "node", "type": "bytes32"},
			{"name": "key", "type": "string"}
		],
		"name": "text",
		"outputs": [
			{"name": "", "type": "string"}
		],
		"stateMutability": "view",
		"type": "function"
	}]`))
	if err != nil {
		panic("failed to parse Space ID text ABI: " + err.Error())
	}
	sidTextABI = parsed

	parsedReg, err := abi.JSON(strings.NewReader(`[{
		"inputs": [
			{"name": "node", "type": "bytes32"}
		],
		"name": "resolver",
		"outputs": [
			{"name": "", "type": "address"}
		],
		"stateMutability": "view",
		"type": "function"
	}]`))
	if err != nil {
		panic("failed to parse Space ID registry ABI: " + err.Error())
	}
	sidRegistryABI = parsedReg

	// TODO: re-enable when Space ID frontend issues are resolved
	// for _, chain := range spaceIDChains {
	// 	c := chain
	// 	RegisterChain(ChainConfig{
	// 		TLD:         c.TLD,
	// 		Name:        c.Name,
	// 		RecordKey:   ADNLRecordKey,
	// 		DefaultRPCs: c.DefaultRPCs,
	// 		NewResolver: func(rpcURL string) (Resolver, error) {
	// 			return newSpaceIDResolver(rpcURL, c)
	// 		},
	// 	})
	// }
}

type SpaceIDResolver struct {
	client   *ethclient.Client
	registry common.Address
}

func newSpaceIDResolver(rpcURL string, chain spaceIDChain) (*SpaceIDResolver, error) {
	client, err := dialEVMWithFallback(rpcURL, chain.TLD)
	if err != nil {
		return nil, err
	}
	return &SpaceIDResolver{
		client:   client,
		registry: common.HexToAddress(chain.Registry),
	}, nil
}

func (r *SpaceIDResolver) Resolve(domain string) (string, error) {
	nameHash, err := ens.NameHash(domain)
	if err != nil {
		return "", fmt.Errorf("namehash %q: %w", domain, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Step 1: Query the registry to get the resolver for this domain
	regCallData, err := sidRegistryABI.Pack("resolver", nameHash)
	if err != nil {
		return "", fmt.Errorf("pack registry call: %w", err)
	}

	regResult, err := r.client.CallContract(ctx, ethereum.CallMsg{
		To:   &r.registry,
		Data: regCallData,
	}, nil)
	if err != nil {
		return "", fmt.Errorf("query registry for %q: %w", domain, err)
	}

	regOutput, err := sidRegistryABI.Unpack("resolver", regResult)
	if err != nil {
		return "", fmt.Errorf("unpack registry result for %q: %w", domain, err)
	}

	resolverAddr, ok := regOutput[0].(common.Address)
	if !ok || resolverAddr == (common.Address{}) {
		return "", fmt.Errorf("no resolver set for %q", domain)
	}

	// Step 2: Call text("adnl") on the actual resolver
	callData, err := sidTextABI.Pack("text", nameHash, ADNLRecordKey)
	if err != nil {
		return "", fmt.Errorf("pack text call: %w", err)
	}

	result, err := r.client.CallContract(ctx, ethereum.CallMsg{
		To:   &resolverAddr,
		Data: callData,
	}, nil)
	if err != nil {
		return "", fmt.Errorf("call resolver for %q: %w", domain, err)
	}

	output, err := sidTextABI.Unpack("text", result)
	if err != nil {
		return "", fmt.Errorf("unpack result for %q: %w", domain, err)
	}

	adnlAddr, ok := output[0].(string)
	if !ok {
		return "", fmt.Errorf("unexpected result type for %q", domain)
	}
	if adnlAddr == "" {
		return "", fmt.Errorf("no ADNL record set for %q", domain)
	}

	if _, err := ParseADNLAddress(adnlAddr); err != nil {
		return "", fmt.Errorf("invalid ADNL record for %q: %w", domain, err)
	}

	return adnlAddr, nil
}

func (r *SpaceIDResolver) Close() {
	r.client.Close()
}
