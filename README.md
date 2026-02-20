# Sleuth

- Domain infrastructure scanning (DNS, HTTP headers, TLS/SSL analysis)
- Subdomain enumeration via subfinder
- Vulnerability scanning via Nuclei integration
- CDN, cloud provider, and WAF detection via cdncheck
- Technology fingerprinting via Wappalyzer
- Threat intelligence feed hydration and scoring
- Account signup risk scoring API with actionable recommendations
- OpenAPI/Swagger documentation and generated Go client

## Account Signup Scoring

Sleuth provides a scoring API to help make informed decisions about user account signups. Submit an email, domain, or both and receive:

- **Risk Score** (0-100): higher scores indicate greater risk
- **Risk Level**: none, low, medium, high, or critical
- **Recommendation**: approve, review, or reject
- **Boolean Flags**: quick checks for common risk categories
- **Reasons**: human-readable explanations for the score

## Threat Intelligence

The intel subsystem loads feeds from `config/feed_config.json`, hydrates them into memory, applies indicator-type filtering, caches DNS lookups, and returns scoring results with category and feed summaries.

## Development

### Prerequisites

- Go 1.25+
- [Task](https://taskfile.dev) (task runner)
- [golangci-lint](https://golangci-lint.run) (linting)
- Docker (for container builds)

### Performance Notes

- Scoring requests typically complete in <100ms
- Feed hydration takes 5-15 minutes and should be run periodically
