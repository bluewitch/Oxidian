# Oxidian

Self-hosted attack-surface mapper in Rust. Discovers your domains, hosts and services, then flags anything matching actively exploited CVEs. Allowlist-only: scan what you own.

> **Early development, not production-ready.** Interfaces, the schema, and matching rules will change. Do not point this at anything you cannot afford to probe, and do not expose the API beyond localhost.

## Legal and ethical notice

Use Oxidian only on systems you own or have written permission to test. You are responsible for complying with the law where you run it. The allowlist is a technical backstop, not a substitute for authorization. Oxidian does not exploit vulnerabilities, does not ship payloads, and refuses to run without an explicit allowlist of domains and networks.

This project is a clean-room design. Do not copy code, schemas, or data models from cvENGINE/CVEngine or reNgine.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Quickstart

Rust stable (see `rust-toolchain.toml`) and, for active scans, `naabu` and `nmap` on `PATH`.

```bash
cp examples/lab.toml oxidian.toml
# Edit the allowlist so it names only systems you own.

docker compose up -d

export OXIDIAN_DATABASE_URL=postgres://oxidian:oxidian-dev-only@127.0.0.1:5432/oxidian
export OXIDIAN_API_TOKEN=replace-with-at-least-16-chars
# export OXIDIAN_WEBHOOK_URL=https://example.invalid/webhook

cargo run -p oxidian -- discover --config oxidian.toml
cargo run -p oxidian -- intel sync --config oxidian.toml
cargo run -p oxidian -- scan --config oxidian.toml
cargo run -p oxidian -- serve --config oxidian.toml
```

`discover` is passive (certificate transparency and DNS). `scan` is active and runs only against allowlisted CIDRs. A domain-only allowlist is refused by `scan`.

The API listens on `127.0.0.1:8080` by default.

```bash
curl -s http://127.0.0.1:8080/health
curl -s -H "Authorization: Bearer $OXIDIAN_API_TOKEN" http://127.0.0.1:8080/findings
```

`OXIDIAN_DATABASE_URL` is optional for `discover` and `scan`. When it is set, those commands migrate and write the inventory. `serve` requires it. The Postgres password in `docker-compose.yml` is a local placeholder.

## Example configuration

[`examples/lab.toml`](examples/lab.toml) lists `example.com` and `192.0.2.0/24`. Those are documentation ranges (RFC 2606 and RFC 5737), not targets to probe. An optional product catalog lives at [`examples/advisories.json`](examples/advisories.json). Point `intel.advisories_path` at a file of that shape when you want `scan` to rank findings. The sample row uses a synthetic CVE id.

## How matching works

A service becomes a finding only when its product name and a parsed version both agree with a bounded version range on an advisory. Known Exploited Vulnerabilities membership sorts above EPSS, which sorts above CVSS. Unbounded "all versions" rows are ignored.

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the data flow, crate map, threat model, and roadmap.
