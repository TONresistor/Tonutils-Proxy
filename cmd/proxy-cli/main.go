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
)

var GitCommit = "dev"

func main() {
	var addr = flag.String("addr", "127.0.0.1:8080", "The addr of the proxy.")
	var verbosity = flag.Int("verbosity", 2, "Debug logs")
	var blockHttp = flag.Bool("no-http", false, "Block ordinary http requests")
	var networkConfigPath = flag.String("global-config", "", "path to ton network config file")
	var tunnelSections = flag.Int("tunnel", 0, "Number of tunnel sections (0=direct, 2+=tunnel with DHT relay discovery)")

	flag.Parse()

	if *tunnelSections == 1 {
		log.Fatal().Msg("--tunnel requires at least 2 sections (use --tunnel 2 or higher)")
	}

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout}).Level(zerolog.InfoLevel)
	if *verbosity >= 3 {
		log.Logger = log.Logger.Level(zerolog.DebugLevel)
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

	go func() {
		err = proxy.RunProxy(closerCtx, *addr, cfg.ADNLKey, nil, "CLI "+GitCommit, *blockHttp, *networkConfigPath, cfg.TunnelConfig, customTinNetCfg)
		if err != nil {
			log.Fatal().Err(err).Msg("proxy failed")
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	stop()

	log.Info().Msg("Received interrupt signal, shutting down...")
	if tunnelEnabled {
		log.Info().Msg("Waiting for tunnel to stop...")
		<-tunnelCtx.Done()
	}
	log.Info().Msg("Shutdown complete")
}
