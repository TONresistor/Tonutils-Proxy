package main

import (
	"context"
	"flag"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	tunnelConfig "github.com/ton-blockchain/adnl-tunnel/config"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-proxy/cmd/proxy-cli/config"
	"github.com/xssnick/tonutils-proxy/proxy"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var GitCommit = "dev"

func main() {
	var addr = flag.String("addr", "127.0.0.1:8080", "The addr of the proxy.")
	var verbosity = flag.Int("verbosity", 2, "Debug logs")
	var blockHttp = flag.Bool("no-http", false, "Block ordinary http requests")
	var networkConfigPath = flag.String("global-config", "", "path to ton network config file")
	var tunnelSections = flag.Int("tunnel", 0, "Number of tunnel sections (0=direct, 2+=tunnel with DHT relay discovery)")
	var ethRPC = flag.String("eth-rpc", "", "Custom Ethereum RPC endpoint for ENS resolution")
	var noEth = flag.Bool("no-eth", false, "Disable .eth domain resolution")
	var solRPC = flag.String("sol-rpc", "", "Custom Solana RPC endpoint for SNS resolution")
	var noSol = flag.Bool("no-sol", false, "Disable .sol domain resolution")
	var noConnect = flag.Bool("no-connect", false, "Disable CONNECT tunnel support")
	var clearnet = flag.Bool("clearnet", false, "Route HTTPS CONNECT through tunnel exit nodes (requires --tunnel)")

	flag.Parse()

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout}).Level(zerolog.InfoLevel)
	if *verbosity >= 3 {
		log.Logger = log.Logger.Level(zerolog.DebugLevel)
	}

	if *tunnelSections == 1 {
		log.Fatal().Msg("--tunnel requires at least 2 sections (use --tunnel 2 or higher)")
	}

	if *clearnet && *tunnelSections < 2 {
		log.Fatal().Msg("--clearnet requires --tunnel N (N >= 2)")
	}

	log.Info().Msg("Version:" + GitCommit)
	if *blockHttp {
		log.Info().Msg("Ordinary HTTP Will be blocked (flag --no-http set)")
	}

	cfg, err := config.LoadConfig("./")
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	var customTinNetCfg *liteclient.GlobalConfig
	if cfg.CustomTunnelNetworkConfigPath != "" {
		customTinNetCfg, err = liteclient.GetConfigFromFile(cfg.CustomTunnelNetworkConfigPath)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to load custom net config for tun")
		}
	}

	if cfg.TunnelConfig == nil {
		cfg.TunnelConfig = &tunnelConfig.ClientConfig{}
	}
	// --tunnel flag overrides config: use DHT discovery (free relays), no payments.
	// Without it, respect config.json (used by Tonnet-Browser GUI).
	if *tunnelSections > 0 {
		cfg.TunnelConfig.TunnelSectionsNum = uint(*tunnelSections)
		cfg.TunnelConfig.NodesPoolConfigPath = ""
		cfg.TunnelConfig.PaymentsEnabled = false
	}

	tunnelEnabled := cfg.TunnelConfig.TunnelSectionsNum >= 2 || cfg.TunnelConfig.NodesPoolConfigPath != ""
	closerCtx, stop := context.WithCancel(context.Background())

	var tunnelCtx context.Context
	if tunnelEnabled {
		var cancel context.CancelFunc
		tunnelCtx, cancel = context.WithCancel(context.Background())
		proxy.OnTunnelStopped = cancel
	}

	// Build multi-chain resolver config: config file as base, CLI flags override
	var multiChainCfg *proxy.MultiChainConfig
	if cfg.Resolver != nil || *ethRPC != "" || *noEth || *solRPC != "" || *noSol {
		multiChainCfg = &proxy.MultiChainConfig{
			RPCOverrides: make(map[string]string),
			Disabled:     make(map[string]bool),
		}
		if cfg.Resolver != nil {
			for k, v := range cfg.Resolver.RPCOverrides {
				multiChainCfg.RPCOverrides[k] = v
			}
			for _, tld := range cfg.Resolver.Disabled {
				multiChainCfg.Disabled[tld] = true
			}
		}
		if *ethRPC != "" {
			multiChainCfg.RPCOverrides[".eth"] = *ethRPC
		}
		if *noEth {
			multiChainCfg.Disabled[".eth"] = true
		}
		if *solRPC != "" {
			multiChainCfg.RPCOverrides[".sol"] = *solRPC
		}
		if *noSol {
			multiChainCfg.Disabled[".sol"] = true
		}
	}

	if multiChainCfg != nil {
		for k := range multiChainCfg.RPCOverrides {
			if !strings.HasPrefix(k, ".") {
				log.Warn().Str("key", k).Msg("RPCOverrides key should start with dot, e.g. '." + k + "'")
			}
		}
	}

	var connectCfg *proxy.ConnectConfig
	if *noConnect {
		// CLI explicitly disabled CONNECT
		connectCfg = nil
	} else if cfg.Connect != nil && cfg.Connect.Enabled {
		// Config file enables CONNECT
		connectCfg = &proxy.ConnectConfig{
			Enabled:      true,
			AllowedPorts: cfg.Connect.AllowedPorts,
			MaxTunnels:   cfg.Connect.MaxTunnels,
			DialTimeout:  time.Duration(cfg.Connect.DialTimeout) * time.Second,
			IdleTimeout:  time.Duration(cfg.Connect.IdleTimeout) * time.Second,
		}
	}

	go func() {
		err = proxy.RunProxy(closerCtx, *addr, cfg.ADNLKey, nil, "CLI "+GitCommit, *blockHttp, *networkConfigPath, cfg.TunnelConfig, customTinNetCfg, multiChainCfg, connectCfg, *clearnet)
		if err != nil {
			log.Fatal().Err(err).Msg("proxy failed")
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	stop()

	log.Info().Msg("Received interrupt signal, shutting down...")
	if tunnelEnabled {
		log.Info().Msg("Waiting for tunnel to stop...")
		select {
		case <-tunnelCtx.Done():
		case <-time.After(10 * time.Second):
			log.Warn().Msg("Tunnel did not stop within timeout")
		}
	}
	log.Info().Msg("Shutdown complete")
}
