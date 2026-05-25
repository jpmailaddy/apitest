# apitest

External API security posture scanner. Classifies an API endpoint
(REST / SOAP / GraphQL / gRPC-web), fingerprints the server, enumerates
endpoints, and surfaces OWASP API Top 10 misconfigurations — with replay
curl commands ready for manual follow-up.

Authorized testing only. Every scan requires a typed confirmation and a
written reason, and is appended to a hash-chained audit log at
`~/.apitest/scans.log`.

## Install

```
go install github.com/jpmailaddy/apitest/cmd/apitest@latest
```

Or build from source:

```
git clone https://github.com/jpmailaddy/apitest.git
cd apitest
go build -o bin/apitest ./cmd/apitest
```

Single static binary. No CGO. Tested on Go 1.23+.

## Usage

```
apitest scan <url> [flags]
```

Minimal:

```
apitest scan https://api.example.com -d -y -r "Engagement XYZ-2025"
```

Full discovery with a wordlist, behind Burp, with auth:

```
apitest scan https://api.example.com \
  -w /path/to/api_wordlist.txt \
  -H 'Authorization: Bearer eyJ...' \
  --proxy http://127.0.0.1:8080 \
  -k \
  --rps 50 \
  -o report.json \
  -y -r "Authorized pentest, scope ticket #1234"
```

### Flags

| Flag | Description |
|------|-------------|
| `-d, --discover` | Enumerate endpoints (built-in mini-list of ~130 paths) |
| `-w, --wordlist <path>` | Custom wordlist (implies `--discover`) |
| `-c, --concurrency N` | Worker count (default 100) |
| `--rps N` | Cap total requests per second |
| `-H, --header <line>` | Custom header, repeatable (e.g. `Authorization: Bearer …`) |
| `--proxy <url>` | Route all requests through a proxy (Burp Suite etc.) |
| `-k, --insecure` | Skip TLS verification |
| `--timeout N` | Per-request timeout in seconds (default 15) |
| `-o, --output <file>` | Write JSON report to file |
| `-y, --yes` | Skip interactive authorization prompt |
| `-r, --reason <str>` | Authorization reason (required with `--yes`) |
| `--quiet` | Suppress progress on stderr |

`apitest scan --help` lists everything.

## What it produces

A single JSON report with:

- **classify** — API type (rest / soap / graphql / grpc-web), confidence, evidence, spec URL if found
- **fingerprint** — product/version extracted from `Server`, `X-Powered-By`, etc.
- **openapi** — parsed spec (when `/openapi.json` or `/swagger.json` is found): all documented endpoints with method, parameters, auth requirement, tags
- **graphql** — full schema dump when introspection is open: queries, mutations, args, return types
- **discover** — endpoints found via wordlist + HTML crawling + method probing; each with a ready-to-paste `replay` curl
- **vulnerabilities** — OWASP API Top 10 findings: CORS misconfigurations, missing security headers, exposed debug consoles, GraphQL introspection in prod, verbose error traces, sensitive paths

Every finding includes a stable ID (`APITEST-CORS-REFLECTIVE-ORIGIN`), severity
(info/low/medium/high/critical), OWASP category tag, evidence, and remediation
guidance.

## Checks implemented

| ID prefix | What it catches |
|-----------|-----------------|
| `APITEST-CORS-*` | Wildcard ACAO, wildcard with credentials, reflective Origin |
| `APITEST-HEADER-*` | Missing X-Content-Type-Options, X-Frame-Options, CSP, HSTS, Referrer-Policy; Server / X-Powered-By disclosure |
| `APITEST-DEBUG-*` | Werkzeug `/console`, Spring `/actuator/*`, Go `/debug/pprof`, `.git/HEAD`, `.env`, Apache mod_status/mod_info, WordPress user-enum |
| `APITEST-GRAPHQL-INTROSPECTION-ENABLED` | Introspection open on a public endpoint |
| `APITEST-VERBOSE-ERROR` | Python/Java/Spring/PHP/Rails/ASP.NET stack traces in body |
| `APITEST-SENSITIVE-*` | `/admin`, `/backup`, `/secret`, `/private`, `/config`, `/debug` reachable |

## Status

v1: feature-complete CLI scanner.

Planned v2: local web dashboard (server + SQLite-backed scan history) on top
of the same scanner library. CLI continues working unchanged.
