package main

import (
	"context"
	"flag"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-proxy/cmd/proxy-cli/config"
	"github.com/xssnick/tonutils-proxy/proxy"
	"os"
	"os/signal"
	"syscall"
)

var GitCommit = "dev"

func main() {
	var addr = flag.String("addr", "127.0.0.1:8080", "The addr of the proxy.")
	var verbosity = flag.Int("verbosity", 2, "Debug logs")
	var blockHttp = flag.Bool("no-http", false, "Block ordinary http requests")
	var networkConfigPath = flag.String("global-config", "", "path to ton network config file")

	flag.Parse()

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

	closerCtx, stop := context.WithCancel(context.Background())

	go func() {
		err = proxy.RunProxy(closerCtx, *addr, cfg.ADNLKey, nil, "CLI "+GitCommit, *blockHttp, *networkConfigPath)
		if err != nil {
			log.Fatal().Err(err).Msg("proxy failed")
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	stop()

	log.Info().Msg("Received interrupt signal, shutting down...")
	log.Info().Msg("Shutdown complete")
}
