# Changelog

All notable changes to this fork are documented here.

Forked from [xssnick/Tonutils-Proxy](https://github.com/xssnick/Tonutils-Proxy) at `bfcf778` (2025-11-02).

## [Unreleased]

### Added

- **Multi-chain domain resolution**: resolve `.eth` (ENS) and `.sol` (SNS) domains to TON Sites via ADNL addresses
  - ENS: on-chain L1 text record `adnl`, 4 public RPC fallbacks, 10s timeout
  - SNS: V2 records (sns.id) with V1 fallback, full header parsing per SNS-IP-3
  - Space ID `.bnb` support included but disabled pending frontend issues (enable with `-tags spaceid`)
- **Resolver package** (`resolver/`): pluggable multi-chain registry with cache (TTL 5min), parallel init, ADNL serialization
- **Resolver config persistence**: `config.json` now supports `Resolver.RPCOverrides` and `Resolver.Disabled` fields
- **CLI flags**: `--eth-rpc`, `--no-eth`, `--sol-rpc`, `--no-sol` for per-chain RPC override and disable
- **GUI/lib support**: mobile entry point reads resolver config from `config.json` instead of hardcoded nil
- **24 unit tests** for ADNL serialization, cache, SNS V1/V2 parsing, edge cases
- **DHT tunnel relay discovery** (`--tunnel N`): discovers relay nodes from the DHT overlay at startup, falls back to static pool file if present
- **CI/CD pipeline**: build, vet, staticcheck, cross-compile (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64), auto-release on `v*` tags
- **Android builds**: NDK r27b, `c-shared` for arm64-v8a and armeabi-v7a

### Fixed

- **RLDP client cache**: dead connections are now destroyed after failed requests (was silently reused)
- **CLI config respect**: `config.json` tunnel/payment settings preserved when `--tunnel` is not passed (used by GUI)
- **Proxy shutdown**: `server.Shutdown()` used a cancelled context, now uses fresh 5s timeout
- **Android arm32**: correct NDK compiler triple (`androideabi`, not `android`)
- **DHT discovery timeout**: 90s for `discoverTunnelNodes` (3 rounds with continuation)
- **Upstream staticcheck**: `strings.TrimPrefix` (S1017), redundant return (S1023)
- **Dead code**: removed unused CLI code after `log.Fatal()`

### Changed

- `--tunnel 1` rejected (minimum 2 sections required)
- CLI shutdown message: "Waiting for tunnel to stop..." (was "Committing tunnel payments...")
