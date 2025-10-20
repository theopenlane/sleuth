# Sleuth

A domain analysis sidecar service for Openlane that performs comprehensive security and technology detection on user registration domains.

## Features

Sleuth performs the following checks on domains:

- **CNAME Takeover Detection**: Identifies potential subdomain takeover vulnerabilities
- **DNS Record Analysis**: Examines DNS configurations including MX, TXT, SPF, and DMARC records
- **Technology Detection**: Identifies CMS, frameworks, analytics, and hosting providers
- **Security Headers Analysis**: Checks for critical security headers and TLS configuration
- **SSL/TLS Certificate Validation**: Verifies certificate validity and configuration

## Architecture

Sleuth runs as a sidecar service alongside your main Openlane application. On user signup, it receives the domain from the user's email address and performs comprehensive analysis to surface interesting findings.

## Installation

### Using Go

```bash
go install github.com/theopenlane/sleuth@latest
```

### Using Docker

```bash
docker pull ghcr.io/theopenlane/sleuth:latest
```

### From Source

```bash
git clone https://github.com/theopenlane/sleuth.git
cd sleuth
task build
```

## Configuration

Sleuth uses environment variables for configuration:

| Variable | Default | Description |
|----------|---------|-------------|
| `SLEUTH_PORT` | `8080` | HTTP server port |
| `SLEUTH_READ_TIMEOUT` | `30s` | HTTP read timeout |
| `SLEUTH_WRITE_TIMEOUT` | `30s` | HTTP write timeout |
| `SLEUTH_SHUTDOWN_TIMEOUT` | `30s` | Graceful shutdown timeout |
| `SLEUTH_SCAN_TIMEOUT` | `60s` | Maximum scan duration |
| `SLEUTH_MAX_BODY_SIZE` | `102400` | Maximum request body size (100KB) |
| `SLEUTH_INTEL_FEED_CONFIG` | `config/feed_config.json` | Path to the OSINT feed configuration file |
| `SLEUTH_INTEL_STORAGE_DIR` | `data/intel` | Directory where hydrated threat intelligence data is stored |
| `SLEUTH_INTEL_AUTO_HYDRATE` | `false` | Automatically hydrate feeds during service startup |
| `SLEUTH_INTEL_REQUEST_TIMEOUT` | `90s` | Timeout for downloading a single feed |
| `SLEUTH_INTEL_RESOLVER_TIMEOUT` | `10s` | Timeout for DNS lookups when scoring indicators |
| `SLEUTH_INTEL_DNS_CACHE_TTL` | `5m` | How long DNS lookup results are cached when resolving domains |

Threat-intel feeds can optionally declare an `indicators` array inside `config/feed_config.json` to restrict ingestion to specific observable types (`ip`, `cidr`, `domain`, `email`). When omitted, Sleuth will attempt to infer the indicator type of each line automatically.

## API Usage

### Health Check

```bash
GET /health
```

Response:
```json
{
  "status": "healthy",
  "service": "sleuth",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Domain Scan

```bash
POST /scan
Content-Type: application/json

{
  "email": "user@example.com"
}
```

Or directly with domain:

```bash
POST /scan
Content-Type: application/json

{
  "domain": "example.com"
}
```

Response:
```json
{
  "success": true,
  "data": {
    "domain": "example.com",
    "scanned_at": "1705316400",
    "domain_info": {
      "domain": "example.com",
      "tld": "com",
      "sld": "example"
    },
    "results": [
      {
        "check_name": "cname_takeover",
        "status": "pass",
        "findings": []
      },
      {
        "check_name": "dns_records",
        "status": "pass",
        "findings": [
          {
            "severity": "info",
            "type": "email_provider",
            "description": "Email hosted by Google Workspace",
            "details": "MX record: aspmx.l.google.com"
          }
        ],
        "metadata": {
          "records": {
            "A": ["93.184.216.34"],
            "MX": ["10 aspmx.l.google.com"],
            "TXT": ["v=spf1 include:_spf.google.com ~all"]
          }
        }
      }
    ]
  }
}
```

### Hydrate Threat Intelligence Feeds

```bash
POST /intel/hydrate
```

Response:
```json
{
  "success": true,
  "summary": {
    "total_feeds": 120,
    "successful_feeds": 118,
    "failed_feeds": 2,
    "total_indicators": 3852045,
    "errors_encountered": true
  }
}
```

### Score an Email or Domain Against Threat Feeds

```bash
POST /intel/check
Content-Type: application/json

{
  "email": "user@example.com",
  "domain": "example.com",
  "indicator_types": ["domain", "email"],
  "include_resolved_ips": false
}
```

Response:
```json
{
  "success": true,
  "data": {
    "domain": "example.com",
    "score": 45,
    "matches": [
      {
        "value": "malicious.example.com",
        "type": "domain",
        "match_context": "domain example.com",
        "categories": ["suspicious"],
        "feeds": ["alienvault_reputation_generic"]
      }
    ],
    "category_breakdown": [
      {"category": "suspicious", "weight": 20},
      {"category": "c2", "weight": 25}
    ],
    "issues": [
      "dns lookup failed for example.com: lookup example.com: no such host"
    ]
  }
}
```

`indicator_types` accepts any combination of `domain`, `email`, `ip`, or `cidr`. When omitted, Sleuth defaults to the most relevant indicator types for the provided inputs (e.g., domain lookups only evaluate domain-sourced intelligence by default). Set `include_resolved_ips` to `true` when you want domain lookups to also evaluate the resolved IP addresses against IP/CIDR feeds.

## Integration with Openlane

### Example Integration (Go)

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
)

type SleuthClient struct {
    baseURL string
    client  *http.Client
}

func NewSleuthClient(baseURL string) *SleuthClient {
    return &SleuthClient{
        baseURL: baseURL,
        client:  &http.Client{},
    }
}

func (s *SleuthClient) ScanDomain(email string) (*ScanResponse, error) {
    payload := map[string]string{"email": email}
    body, _ := json.Marshal(payload)
    
    resp, err := s.client.Post(
        fmt.Sprintf("%s/scan", s.baseURL),
        "application/json",
        bytes.NewBuffer(body),
    )
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result ScanResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }
    
    return &result, nil
}

// Usage in signup flow
func HandleUserSignup(email string) {
    // ... existing signup logic ...
    
    // Scan domain asynchronously
    go func() {
        sleuth := NewSleuthClient("http://sleuth:8080")
        result, err := sleuth.ScanDomain(email)
        if err != nil {
            log.Printf("Domain scan failed: %v", err)
            return
        }
        
        // Process findings
        for _, check := range result.Data.Results {
            for _, finding := range check.Findings {
                if finding.Severity == "high" || finding.Severity == "critical" {
                    // Alert user about security issues
                    notifyUserAboutFinding(email, finding)
                }
            }
        }
    }()
}
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openlane-app
spec:
  template:
    spec:
      containers:
      - name: openlane
        image: openlane:latest
        ports:
        - containerPort: 3000
        env:
        - name: SLEUTH_URL
          value: "http://localhost:8080"
      
      - name: sleuth
        image: ghcr.io/theopenlane/sleuth:latest
        ports:
        - containerPort: 8080
        env:
        - name: SLEUTH_PORT
          value: "8080"
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"
```

## Development

### Prerequisites

- Go 1.21+
- Task (taskfile.dev)

### Running Locally

```bash
# Install dependencies
task deps

# Run the service
task run

# Run tests
task test

# Build binary
task build
```

### Available Tasks

```bash
task --list-all
```

## Security Considerations

- Sleuth performs external network requests to analyze domains
- It respects robots.txt and implements rate limiting
- No domain data is stored persistently
- All scans are performed in real-time

## Findings Reference

### Severity Levels

- **critical**: Immediate security risk (e.g., expired SSL certificate)
- **high**: Significant security issue (e.g., CNAME takeover vulnerability)
- **medium**: Security improvement needed (e.g., missing security headers)
- **low**: Minor issue or recommendation
- **info**: Informational finding (e.g., technology detected)

### Common Findings

1. **CNAME Takeover**: Subdomain points to unclaimed service
2. **Weak SPF**: SPF record allows all servers (+all)
3. **Missing Security Headers**: No HSTS, X-Frame-Options, etc.
4. **Expired Certificate**: SSL certificate has expired
5. **Exposed Files**: Sensitive files like .git, .env accessible

## License

See [LICENSE](LICENSE) file for details.
