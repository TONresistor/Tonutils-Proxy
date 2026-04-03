package main

import "C"
import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-proxy/cmd/proxy-cli/config"
	"github.com/xssnick/tonutils-proxy/proxy"
	"log"
)

var GitCommit string

func main() {}

var ActiveProxy context.Context
var ProxyStopper context.CancelFunc

func init() {
	ActiveProxy, ProxyStopper = context.WithCancel(context.Background())
	ProxyStopper() // mark it not started
}

//export StartProxy
func StartProxy(port C.ushort) *C.char {
	return C.CString(startProxy(uint16(port), nil))
}

//export StartProxyWithConfig
func StartProxyWithConfig(port C.ushort, configTextJSON *C.char) *C.char {
	var cfg liteclient.GlobalConfig
	if err := json.Unmarshal([]byte(C.GoString(configTextJSON)), &cfg); err != nil {
		log.Println("failed to parse config:", err.Error())
		return C.CString("PARSE_CONFIG_ERR: " + err.Error())
	}

	return C.CString(startProxy(uint16(port), &cfg))
}

//export StopProxy
func StopProxy() *C.char {
	ProxyStopper()
	return C.CString("OK")
}

func startProxy(port uint16, netCfg *liteclient.GlobalConfig) string {
	select {
	case <-ActiveProxy.Done():
	default:
		return "ALREADY_STARTED"
	}

	ActiveProxy, ProxyStopper = context.WithCancel(context.Background())

	// Load config.json from CWD (same as CLI)
	cfg, err := config.LoadConfig("./")
	if err != nil {
		log.Println("failed to load config:", err.Error())
		return "ERR: " + err.Error()
	}

	var customTunNetCfg *liteclient.GlobalConfig
	if cfg.CustomTunnelNetworkConfigPath != "" {
		customTunNetCfg, err = liteclient.GetConfigFromFile(cfg.CustomTunnelNetworkConfigPath)
		if err != nil {
			log.Println("failed to load custom net config for tun:", err.Error())
		}
	}

	var multiChainCfg *proxy.MultiChainConfig
	if cfg.Resolver != nil {
		multiChainCfg = &proxy.MultiChainConfig{
			RPCOverrides: make(map[string]string),
			Disabled:     make(map[string]bool),
		}
		for k, v := range cfg.Resolver.RPCOverrides {
			multiChainCfg.RPCOverrides[k] = v
		}
		for _, tld := range cfg.Resolver.Disabled {
			multiChainCfg.Disabled[tld] = true
		}
	}

	var ch = make(chan proxy.State, 1)
	go func() {
		if netCfg != nil {
			err = proxy.RunProxyWithConfig(ActiveProxy, "127.0.0.1:"+fmt.Sprint(port), cfg.ADNLKey, ch, false, "LIB "+GitCommit, netCfg, cfg.TunnelConfig, customTunNetCfg, multiChainCfg)
		} else {
			err = proxy.RunProxy(ActiveProxy, "127.0.0.1:"+fmt.Sprint(port), cfg.ADNLKey, ch, "LIB "+GitCommit, false, "", cfg.TunnelConfig, customTunNetCfg, multiChainCfg)
		}
		if err != nil {
			log.Println("failed to start proxy:", err.Error())
			ch <- proxy.State{Type: "error", State: err.Error(), Stopped: true}
		}
	}()

	var res = make(chan string, 1)
	go func() {
		for {
			select {
			case <-ActiveProxy.Done():
				return
			case state := <-ch:
				if state.Stopped {
					ProxyStopper()
					select {
					case res <- "ERR: " + state.State:
					default:
					}
					return
				} else if state.Type == "ready" {
					select {
					case res <- "OK":
					default:
					}
				}
				// "loading" states are ignored — keep waiting
			}
		}
	}()

	return <-res
}
