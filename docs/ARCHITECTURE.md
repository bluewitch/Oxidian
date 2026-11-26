# Oxidian architecture

Oxidian is a self-hosted attack-surface mapper. An operator lists domains and networks they own. The tool records what it can see inside that allowlist and ranks services whose product and version fall inside a known vulnerable range, with extra weight for CISA Known Exploited Vulnerabilities (KEV) and FIRST EPSS.

## Goals

- Inventory the operator's own names, addresses, and exposed services.
- Fail closed: every command that touches the outside world requires a non-empty allowlist, and every result is filtered through it again.
- Rank findings from public vulnerability feeds. KEV membership outranks EPSS, which outranks CVSS.
- Keep the tool small enough to audit. v1 is a Rust workspace with a Postgres inventory and a localhost API.
- Stay a clean-room project. Types, table names, and control flow are original.

## Non-goals

- No AI features in v1. No model calls, no embeddings, no generated exploits.
- No exploitation. Oxidian does not run attack payloads, proof-of-concept code, or brute-force logins. `nmap` is invoked for version detection only (`-sV`) together with a TCP connect scan (`-sT`). NSE scripts are not enabled.
- No scanning outside the allowlist. Domains that are not the listed name or a subdomain of it are dropped. Addresses that are not inside a listed CIDR are dropped. `scan` refuses to run when the allowlist has no CIDR, so a domain list alone cannot start packets.
- No default hosts. Feed URLs are overridable configuration for public vulnerability data. They are not scan targets. Documentation examples use `example.com` and `192.0.2.0/24` only.
- No multi-tenant accounts, no built-in scheduler, and no production hardening claims. The README banner stands.

## Data flow

1. **Discover.** For each allowlisted domain, query a certificate-transparency log (crt.sh by default), keep names that the allowlist admits, then resolve those names. Addresses inside an allowlisted CIDR are stored. Other answers are counted and discarded.
2. **Inventory.** Assets and, after a scan, services are written to Postgres when `OXIDIAN_DATABASE_URL` is set. The API reads that inventory.
3. **Assess.** `scan` runs naabu, then `nmap -sV`, against allowlisted CIDRs only. Open ports become `Service` values. Optional local advisory JSON supplies product and version ranges. A service matches only when the normalized product is equal and the version sits inside a bounded range.
4. **Prioritize.** Each match is scored as KEV (1000) + EPSS (0–100) + CVSS (0–10). The list is ordered by that score, then by CVE id.
5. **Alert.** When `OXIDIAN_WEBHOOK_URL` is set and at least one finding was produced, Oxidian POSTs a Slack- and Discord-compatible JSON body. The URL is never written to logs.

`intel sync` sits beside this flow. It downloads the KEV catalog and one page of the EPSS API into a local cache. The NVD CVE API 2.0 client can parse a single-CVE document and is not wired into bulk sync.

## Crate layout

| Crate | Role |
| --- | --- |
| `oxidian-core` | `Target`, `Asset`, `Service`, `Finding`, `Severity`, allowlist, TOML config, inventory trait |
| `oxidian-discovery` | crt.sh client (`reqwest` + rustls) and DNS (`hickory-resolver`), both filtered by the allowlist |
| `oxidian-scan` | naabu and nmap subprocesses, JSON and XML parsers, fixture tests |
| `oxidian-intel` | KEV, EPSS, disk cache, stub NVD client |
| `oxidian-match` | Bounded version ranges and ranking |
| `oxidian-store` | sqlx Postgres pool and migrations |
| `oxidian-api` | axum routes: `/health`, `/assets`, `/findings` |
| `oxidian-alert` | Webhook body and POST |
| `oxidian-cli` | `oxidian discover`, `scan`, `intel sync`, `serve` |

The CLI is the composition root. Libraries do not shell out to each other. `oxidian-core` does not depend on HTTP, DNS, or SQL.

## Data model

`Target` is the operator's intent: a domain or a CIDR. It is not stored as an asset.

`Allowlist` compiles those targets. A domain entry must be a registrable-style name (at least two labels, letters, digits, hyphens). A name is admitted when it equals a listed domain or is a subdomain across a dot boundary, so `example.com` admits `www.example.com` and rejects `notexample.com`. A CIDR of prefix length 0 is rejected. An address is admitted only when it falls inside a listed network. A network is admitted only when it is contained by a listed network.

`Asset` is something observed: `domain`, `host` (name plus address), or `address`. `source` records whether it came from certificate transparency or DNS.

`Service` is an open port on an asset: protocol, port, optional product, optional version. Ports are 1–65535. Product strings are matched after stripping non-alphanumeric characters and lowercasing, and only by full equality. `http` is not treated as a product.

`Finding` ties a service to one CVE id: severity, KEV flag, EPSS, CVSS, rank score, and a short summary. Severity comes from CVSS (critical ≥ 9, high ≥ 7, medium ≥ 4, low > 0) and is raised to at least high when the CVE is in KEV.

`Advisory` (match crate) is the local catalog row: CVE id, product, one or more version ranges, optional CVSS. A range must have a start, an end, or both. A range with neither bound cannot match. Versions are dotted integers only; pre-release suffixes do not parse, so they do not match.

## Threat model for the tool itself

Oxidian is a client that stores a map of the operator's attack surface. The threats below are about the tool, not about the networks it maps.

- **Secrets.** The API bearer token, Postgres URL, webhook URL, and optional NVD API key are read from the environment (`OXIDIAN_API_TOKEN`, `OXIDIAN_DATABASE_URL`, `OXIDIAN_WEBHOOK_URL`, `OXIDIAN_NVD_API_KEY`). None are accepted in the TOML file. Errors omit those values. Database errors that mention a URL or a password are replaced with a generic message. Webhook failures report an HTTP status, not the URL or the response body.
- **No hardcoded scan targets.** The binary does not embed hostnames or addresses to probe. The example config uses documentation ranges. Public feed URLs (crt.sh, the CISA KEV file, the FIRST EPSS API, the NVD CVE API) are defaults for data the operator asked to download, and each one can be replaced in config.
- **Least privilege.** The API bind default is `127.0.0.1`. Postgres in `docker-compose.yml` publishes to `127.0.0.1` only. naabu is asked for a connect scan. nmap is passed `-sT` so version detection does not require raw sockets and does not change behavior when the process is root. Child processes start with an empty environment plus `PATH`, so API tokens and database URLs are not inherited.
- **Argument arrays.** External programs are spawned with `tokio::process::Command` and one argument per vector entry. Oxidian never builds a shell string and never invokes a shell. Port lists are restricted to digits, commas, and dashes. Allowlist checks run before any spawn; a rejected target does not look up the binary.
- **Fail closed on parse.** Certificate names, DNS answers, naabu rows, and nmap hosts are passed through the allowlist again after parsing. Advisory rows without a bounded range are dropped. Nmap output is limited to open `tcp` and `udp` ports.
- **Untrusted output.** Tool stdout is capped (32 MiB) and feed bodies are capped (8 MiB). Advisory and cache paths reject `..` components. Cache keys are a single safe filename.
- **What v1 does not defend against.** A hostile operator with a valid token can read the inventory. A compromised feed can lie about CVE metadata; it cannot widen the allowlist. There is no sandbox around naabu or nmap beyond the argument list, the cleaned environment, and the timeout. Review those binaries as you would any other scanner you install.

## External tools

| Tool | Invocation | Parser |
| --- | --- | --- |
| naabu | `-host <cidr> -p <ports> -json -silent -scan-type c` | JSON object or NDJSON |
| nmap | `-n -sT -sV -oX - -p <ports> -- <ip>` | XML via `quick-xml` |

Both binaries must exist and be executable. A missing tool is an error that names the path the operator configured. Tests parse fixture files and never run a scan.

## Roadmap

**v1 (this tree).** Allowlist and config. Passive discovery. Active scan wrappers. KEV and one-page EPSS sync with a disk cache. A stub NVD CVE API 2.0 client (URL builder plus a parser for one CVE document, no bulk crawl). Product and version matching. Postgres migrations. Bearer-token API. Webhook alert. CLI gates.

**Later.**

- Shell out to nuclei for template checks, still allowlist-gated, still an argument array, still no exploit templates in the default set.
- An MCP server implemented with `rmcp`, exposing read-only inventory tools to a local client.
- Optional local-only AI summarization of findings. No cloud model calls in that design; the feature stays off unless the operator points it at a local runtime.

**Not planned.** Exploitation modules, credential attacks, scanning addresses that are merely "related" to an allowlisted name, or a hosted multi-tenant service.
