# Tonutils Proxy
[![Based on TON][ton-svg]][ton]
<img align="right" width="300" alt="proxy" src="https://github.com/xssnick/Tonutils-Proxy/assets/9332353/3806a91c-61bf-4c3c-af6f-55c12ee4f18f">

**Your gateway to the new internet**

This is a user-friendly TON Proxy implementation. It works on any platform with UDP support. It can be used with any internet connection, and any type of ip.  

If you want to run your own web3 sites, use [reverse-proxy](https://github.com/tonutils/reverse-proxy).

[Join our Telegram group](https://t.me/tonrh) to stay updated! More cool products on this basis are planned.

##### Support project ❤️
If you love this product and want to support its development you can donate any amount of coins to this ton address ☺️
`EQBx6tZZWa2Tbv6BvgcvegoOQxkRrVaBVwBOoW85nbP37_Go`

### Download precompiled version
* [Download Mac Apple Silicon (GUI)](https://github.com/xssnick/Tonutils-Proxy/releases/latest/download/GUI.Mac.M1.Tonutils.Proxy.dmg)
* [Download Mac Intel (GUI)](https://github.com/xssnick/Tonutils-Proxy/releases/latest/download/GUI.Mac.Intel.Tonutils.Proxy.dmg)
* [Download Windows (GUI)](https://github.com/xssnick/Tonutils-Proxy/releases/latest/download/Tonutils.Proxy-amd64-installer.exe)
* [Download Linux (CLI)](https://github.com/xssnick/Tonutils-Proxy/releases/latest/download/tonutils-proxy-cli-linux-amd64)
* [Other binaries](https://github.com/xssnick/Tonutils-Proxy/releases)
  
See [How to use](https://github.com/xssnick/Tonutils-Proxy#how-to-use).

### Integrate into your mobile app
You could compile for IOS and Android by yourself using `make build-ios-lib` and `make build-android-lib`. 
To compile for IOS, XCode tools and Mac are required, for Android you need NDK toolchain.

Or you could use precompiled libs.

#### Precompilled
* [Download iOS Library](https://github.com/xssnick/Tonutils-Proxy/releases/latest/download/ios-lib.zip)
* [Download Android Library](https://github.com/xssnick/Tonutils-Proxy/releases/latest/download/android-lib.zip)

##### Community projects
* [Swift wrapper](https://github.com/0xstragner/ton-proxy-swift) for iOS library by [@0xstragner](https://github.com/0xstragner)
* [Kotlin example](https://github.com/andreypfau/tonutils-proxy-android-example) for Android by [@andreypfau](https://github.com/andreypfau)

#### Usage
Connect it as native library to you app, and use available methods:
```c
extern char* StartProxy(unsigned short port);
extern char* StartProxyWithConfig(unsigned short port, char* configTextJSON);
extern char* StopProxy();
```
`StartProxy` will run local http proxy server on `127.0.0.1:port`. 
Use this server as http proxy in your webview component or in any other way.

# How to use

## GUI
#### Start it
Click big blue button, it will configure your system automatically and open foundation.ton.

##### If TON sites not opens
If for some reason your system was not autoconfigured or you don't want to reconfigure it, you can enter HTTP proxy address manually in your browser. Follow CLI instructions starting from [section 2](#2-connect-your-browser-to-it). 

HTTP proxy uses `127.0.0.1:8080` address.

## CLI
##### 1. Open it
Double click on it on windows, or run it using terminal on linux/mac.

<img width="572" alt="Screen Shot 2022-11-18 at 17 01 01" src="https://user-images.githubusercontent.com/9332353/202722168-3a41b771-7f61-4ddd-8310-21ae1b2e5b27.png">

HTTP proxy will start on `127.0.0.1:8080` address.

If you are using GUI version, it should configure your system automatically. 
If you are using CLI, or you want to do a manual connection, follow steps below.

##### 2. Connect your browser to it
Open your browser network settings and configure http proxy.
<img width="735" alt="image" src="https://user-images.githubusercontent.com/9332353/202722921-a2f7a92b-c5d8-496d-aaf2-446f01fad0ae.png">

##### 3. Try to connect to some .ton sites
Your proxy is configured now, you can access TON sites!

Lets try to connect to some ton site, for example http://foundation.ton/

<img width="654" alt="Screen Shot 2022-11-18 at 17 41 19" src="https://user-images.githubusercontent.com/9332353/202730383-85bda07b-7bea-4d9c-9aa6-633f76d1cee3.png">

**By the way, this proxy works fine also for Web2 sites, you can seamlessly use it to access both Web2 and Web3.**

<!-- Badges -->
[ton-svg]: https://img.shields.io/badge/Based%20on-TON-blue
[ton]: https://ton.org

## Multi-Chain Domain Resolution

This fork resolves domains from multiple blockchains to TON Sites via ADNL addresses.

| Chain | TLD | Name Service | Resolution |
|---|---|---|---|
| TON | `.ton`, `.adnl`, `.t.me` | TON DNS | Native |
| Ethereum | `.eth` | [ENS](https://ens.domains/) | On-chain L1, text record `adnl` |
| Solana | `.sol` | [SNS](https://www.sns.id/) | On-chain, TXT record (V2 + V1 fallback) |

Set a text record `adnl` with your 64-char hex ADNL address on your `.eth` or `.sol` domain to link it to a TON Site.

```bash
./proxy-cli                                        # all chains, public RPCs
./proxy-cli --eth-rpc https://your-rpc.com         # custom RPC
./proxy-cli --no-sol                               # disable a chain
```

RPC overrides and disabled chains persist in `config.json` under the `Resolver` key.

### How to build from sources
 ```
go build -o ton-proxy cmd/proxy-cli/main.go
 ```
