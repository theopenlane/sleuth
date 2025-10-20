# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sleuth is a domain analysis sidecar service for Openlane that performs comprehensive security and technology detection on user registration domains. Core functionality includes:

- CNAME takeover detection
- DNS record analysis (MX, TXT, SPF, DMARC)
- Technology detection (CMS, frameworks, analytics, hosting providers)
- Security headers analysis and TLS configuration
- SSL/TLS certificate validation
- Threat intelligence feed integration with domain/email/IP scoring

## Build and Development Commands

### Building and Running
```bash
task build          # Build binary to bin/sleuth
task run            # Run service locally
task deps           # Download and tidy dependencies
task verify         # Build, start, verify endpoints, stop
```

### Testing
```bash
task test                  # Run all tests
task test:short            # Skip integration tests
task test:coverage         # Generate coverage report (coverage.html)
task test:race             # Run with race detection
task test:benchmark        # Run benchmark tests
```

### Code Quality
```bash
task lint           # Run golangci-lint (must pass all findings)
task fmt            # Format code
task vet            # Run go vet
```

### Docker
```bash
task docker:build   # Build Docker image
task docker:run     # Run in Docker
task scan           # Build, start container, scan domain (DOMAIN=example.com)
```

### Local Service Management
```bash
task service:start         # Start service in background
task service:stop          # Stop background service
task service:wait          # Wait for health endpoint
task service:logs          # Tail service logs
```

### API Testing
```bash
task call:health                                    # Health check
task call:scan DOMAIN=example.com                   # Domain scan
task call:scan EMAIL=user@example.com               # Email-based scan
task call:intel-hydrate                             # Download threat feeds
task call:intel-check DOMAIN=example.com TYPES=domain,ip RESOLVE_IPS=true
```

## Architecture

### Main Components

**main.go**: Service entrypoint that initializes:
- Config from environment variables (config/config.go)
- Intel manager (internal/intel/manager.go) with feed configuration
- Scanner (internal/scanner/scanner_v2.go) with domain analysis capabilities
- HTTP router (internal/api/router.go) with chi middleware

**Scanner (internal/scanner/)**: Performs parallel security checks on domains:
- DNS analysis with MX/TXT/SPF/DMARC validation
- Subdomain discovery using projectdiscovery/subfinder
- HTTP analysis (security headers, TLS configuration)
- Technology detection using projectdiscovery/wappalyzergo
- Optional Nuclei vulnerability scanning

The scanner executes checks concurrently using goroutines and channels, collecting results into types.ScanResult.

**Intel Manager (internal/intel/)**: Manages threat intelligence feeds:
- Loads feed configuration from config/feed_config.json
- Downloads and caches feeds to SLEUTH_INTEL_STORAGE_DIR (default: data/intel)
- Parses indicators into in-memory store (domain/email/IP/CIDR)
- Supports indicator-type filtering per feed
- DNS resolution with caching (internal/intel/dns_cache.go)
- Category-based scoring (c2=30, bot=25, suspicious=20, tor=15, bruteforce=15, vpn=10, dc=5, default=10)
- Provides Check() method for scoring domains/emails against feeds

**API Layer (internal/api/)**:
- router.go: chi-based HTTP router with middleware (logger, recoverer, CORS, compression, timeout)
- handler.go: Core scan endpoints (/api/health, /api/scan)
- intel_handlers.go: Intel endpoints (/api/intel/hydrate, /api/intel/check)
- Swagger documentation at /swagger/
- Simple web UI at /ui

### Type Definitions

**internal/types/types.go**: Core scanning types
- ScanResult: Complete domain scan with check results and metadata
- CheckResult: Individual check outcome (dns_analysis, technology_detection, etc.)
- Finding: Security finding with severity/type/description/details
- DomainInfo: Parsed domain components (subdomain, SLD, TLD)

**internal/intel/types.go**: Threat intelligence types
- FeedConfig: Collection of OSINT feed definitions
- Feed: Single feed with name/URL/type/indicators filter
- IndicatorType: Enum (ip, cidr, domain, email)
- CheckRequest: Scoring request with indicator type filtering
- ScoreResult: Score with matches, category breakdown, issues, summary
- IndicatorMatch: Single match with value/type/context/feeds/categories

### Configuration

Environment variables (config/config.go):

**HTTP Server**:
- SLEUTH_PORT (default: 8080)
- SLEUTH_READ_TIMEOUT (default: 30s)
- SLEUTH_WRITE_TIMEOUT (default: 30s)
- SLEUTH_SHUTDOWN_TIMEOUT (default: 30s)
- SLEUTH_SCAN_TIMEOUT (default: 60s)
- SLEUTH_MAX_BODY_SIZE (default: 102400 bytes)

**Threat Intelligence**:
- SLEUTH_INTEL_FEED_CONFIG (default: config/feed_config.json)
- SLEUTH_INTEL_STORAGE_DIR (default: data/intel)
- SLEUTH_INTEL_AUTO_HYDRATE (default: false)
- SLEUTH_INTEL_REQUEST_TIMEOUT (default: 90s)
- SLEUTH_INTEL_RESOLVER_TIMEOUT (default: 10s)
- SLEUTH_INTEL_DNS_CACHE_TTL (default: 5m)

### Key Dependencies

- github.com/go-chi/chi/v5: HTTP router
- github.com/projectdiscovery/subfinder/v2: Subdomain discovery
- github.com/projectdiscovery/dnsx: DNS operations
- github.com/projectdiscovery/wappalyzergo: Technology detection
- github.com/miekg/dns: DNS library
- github.com/swaggo/swag: OpenAPI documentation generation

## Implementation Guidelines

### Scanner Implementation
- Scanner executes checks in parallel using goroutines
- Each check (DNS, HTTP, subdomain, tech detection) returns a types.CheckResult
- Results are collected via channels and aggregated into types.ScanResult
- Scanner options configured via functional options pattern (internal/scanner/options.go)

### Intel Manager Implementation
- Manager.Hydrate() downloads feeds sequentially, stores to disk, parses into memory
- store.ingestFile() respects Feed.Indicators filter (if present) to restrict indicator types
- Manager.Check() evaluates domain/email against in-memory store with optional IP resolution
- DNS lookups are cached via internal/intel/dns_cache.go with configurable TTL
- Scoring uses category weights, caps total score at 100

### API Handler Patterns
- Handlers use JSON request/response with types defined in handler.go
- MaxBodySize middleware enforced via http.MaxBytesReader
- Scan requests accept either "email" (extracts domain) or "domain" directly
- Intel check supports indicator_types filter and include_resolved_ips boolean
- All responses use standard APIResponse wrapper with success/data/error fields

### Error Handling
- Use static error definitions (e.g., intel.ErrNotHydrated)
- Always check error returns
- Return descriptive errors with context

### Testing
- Unit tests in *_test.go files
- Mock scanner interface (internal/scanner/interface.go) for API handler tests
- Integration tests skippable via -short flag
- All new functionality requires unit tests

## Important Notes

- Run `task lint` and address ALL findings before committing
- Use zerolog for logging (imported packages may use standard log)
- Follow Go naming conventions (avoid stuttering like api.APIResponse)
- Use functional options for configurable types (scanner, intel manager)
- All exported functions/consts require godoc comments
- Thread safety: intel.Manager uses sync.RWMutex for store access
- Feed downloads write to temp file then rename atomically
- Scanner.Close() must be called to clean up resources
- Intel feed parsing is line-based with automatic type inference when Feed.Indicators is empty
