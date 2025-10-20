# Sleuth Threat Intel Additions

This note covers the new threat-intel capabilities, how to exercise them locally, and useful configuration knobs.

## What’s New

- **Feed-driven intel manager** (`internal/intel`): loads `config/feed_config.json`, hydrates feeds into memory, applies indicator-type filtering, caches DNS lookups, and returns scoring results with category/feed summaries.
- **Expanded endpoints**:
  - `POST /api/intel/hydrate` downloads/refreshes feeds.
  - `POST /api/intel/check` scores domains/emails with optional `indicator_types` and `include_resolved_ips`.
- **Task automation**: scripts under `scripts/` and Taskfile entries to start/stop the service, wait for readiness, and invoke curl-driven checks.
- **Config knobs**: new env vars for feed path, storage directory, auto-hydration, request/resolver timeouts, and DNS cache TTL.

## Quickstart

Ensure helper scripts are executable once:

```bash
chmod +x scripts/*.sh
```

### Start Sleuth locally

```bash
task service:start
task service:wait                  # waits for /api/health
```

### Hydrate intel feeds

```bash
task call:intel-hydrate
```

### Run a domain scan (main API)

```bash
task call:scan DOMAIN=example.com
```

### Score against intel feeds

```bash
# basic domain check (domain indicators only)
task call:intel-check DOMAIN=example.com TYPES=domain

# include IP resolution & multiple indicator types
task call:intel-check DOMAIN=example.com TYPES=domain,ip RESOLVE_IPS=true

# email-focused lookup
task call:intel-check EMAIL=user@example.com TYPES=email,domain
```

### View logs / stop service

```bash
task service:logs   # follow logs; ctrl+c to exit
task service:stop
```

## Testing

- Run unit tests locally (requires access to Go modules): `go test ./...`.
- Verify indicator filtering by comparing results of `task call:intel-check DOMAIN=example.com TYPES=domain` vs `TYPES=ip`. The former should only report domain feeds.
- Inspect `.tasktmp/sleuth.log` if hydrate or scoring commands fail.

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `SLEUTH_INTEL_FEED_CONFIG` | `config/feed_config.json` | JSON feed list for hydration |
| `SLEUTH_INTEL_STORAGE_DIR` | `data/intel` | Directory for downloaded feed files |
| `SLEUTH_INTEL_AUTO_HYDRATE` | `false` | Trigger hydration automatically on startup |
| `SLEUTH_INTEL_REQUEST_TIMEOUT` | `90s` | Per-feed download timeout |
| `SLEUTH_INTEL_RESOLVER_TIMEOUT` | `10s` | DNS lookup timeout during scoring |
| `SLEUTH_INTEL_DNS_CACHE_TTL` | `5m` | TTL for cached domain resolutions |

Adjust these env vars (or Taskfile `vars`) to suit local/CI environments.

## Handy Commands

| Purpose | Command |
|---------|---------|
| Start service | `task service:start` |
| Stop service | `task service:stop` |
| Tail logs | `task service:logs` |
| Wait for health | `task service:wait` |
| Hydrate feeds | `task call:intel-hydrate` |
| Scan domain | `task call:scan DOMAIN=example.com` |
| Score intel | `task call:intel-check DOMAIN=example.com TYPES=domain` |

