# Account Signup Scoring

This guide explains how to use Sleuth for account signup validation and fraud prevention.

## Overview

Sleuth provides a simple, actionable scoring API to help you make informed decisions about user account signups. Submit an email, domain, or both, and receive:

- **Risk Score** (0-100): Higher scores indicate greater risk
- **Risk Level**: none, low, medium, high, or critical
- **Recommendation**: approve, review, or reject
- **Boolean Flags**: Quick checks for common risk categories
- **Reasons**: Human-readable explanations for the score

## API Endpoint

```
POST /api/intel/check
```

## Request Format

Submit email, domain, or both:

```json
{
  "email": "user@example.com",
  "domain": "example.com",
  "indicator_types": ["domain", "email"],
  "include_resolved_ips": false
}
```

### Request Fields

- `email` (optional): Email address to score
- `domain` (optional): Domain to score
- `indicator_types` (optional): Filter to specific indicator types (domain, email, ip, cidr)
- `include_resolved_ips` (optional): Check domain's resolved IPs against IP/CIDR feeds

**Note**: At least one of `email` or `domain` is required.

## Response Format

```json
{
  "success": true,
  "data": {
    "email": "user@example.com",
    "domain": "example.com",
    "score": 45,
    "risk_level": "medium",
    "recommendation": "review",
    "reasons": [
      "Disposable or temporary email service detected (1 indicator, weight: 20)",
      "Suspicious or malicious activity detected (2 indicators, weight: 40)"
    ],
    "flags": {
      "is_disposable_email": true,
      "is_tor": false,
      "is_vpn": false,
      "is_proxy": false,
      "is_bot": false,
      "is_c2": false,
      "is_spam": false,
      "is_phishing": false,
      "is_malware": false,
      "is_bruteforce": false
    },
    "matches": [...],
    "category_breakdown": [...],
    "summary": {...}
  }
}
```

### Key Response Fields

**Simple Decision Fields**:
- `score`: 0-100 risk score (higher = more risky)
- `risk_level`: none | low | medium | high | critical
- `recommendation`: approve | review | reject
- `reasons`: Array of human-readable strings explaining the score
- `flags`: Boolean indicators for common risk categories

**Detailed Analysis** (optional):
- `matches`: Individual threat intelligence matches
- `category_breakdown`: Category weights contributing to score
- `summary`: Feed and category summaries

## Risk Levels

| Score Range | Risk Level | Recommendation |
|-------------|------------|----------------|
| 0           | none       | approve        |
| 1-20        | low        | approve        |
| 21-50       | medium     | review         |
| 51-75       | high       | review         |
| 76-100      | critical   | reject         |

## Risk Categories and Weights

Categories are weighted based on severity:

| Category    | Weight | Description |
|-------------|--------|-------------|
| c2          | 30     | Command and control infrastructure |
| bot         | 25     | Botnet or malicious bot activity |
| suspicious  | 20     | Suspicious or malicious activity |
| bruteforce  | 15     | Brute force attack source |
| tor         | 15     | Tor network usage |
| vpn         | 10     | VPN service usage |
| spam        | 10     | Spam or unsolicited messaging |
| dc          | 5      | Datacenter or hosting provider |

## Usage Examples

### Example 1: Simple Email Check

**Request**:
```bash
curl -X POST http://localhost:8080/api/intel/check \
  -H "Content-Type: application/json" \
  -d '{"email": "user@suspicious-domain.com"}'
```

**Response**:
```json
{
  "success": true,
  "data": {
    "email": "user@suspicious-domain.com",
    "score": 20,
    "risk_level": "low",
    "recommendation": "approve",
    "flags": {
      "is_disposable_email": false,
      "is_tor": false,
      ...
    }
  }
}
```

### Example 2: Domain with Disposable Email Check

**Request**:
```bash
curl -X POST http://localhost:8080/api/intel/check \
  -H "Content-Type: application/json" \
  -d '{"domain": "tempmail.com", "indicator_types": ["domain"]}'
```

**Response**:
```json
{
  "success": true,
  "data": {
    "domain": "tempmail.com",
    "score": 20,
    "risk_level": "low",
    "recommendation": "approve",
    "reasons": [
      "Disposable or temporary email service detected (1 indicator, weight: 20)"
    ],
    "flags": {
      "is_disposable_email": true,
      ...
    }
  }
}
```

### Example 3: Comprehensive Check with IP Resolution

**Request**:
```bash
curl -X POST http://localhost:8080/api/intel/check \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "domain": "example.com",
    "indicator_types": ["domain", "email", "ip"],
    "include_resolved_ips": true
  }'
```

This will check:
1. The email address against email feeds
2. The domain against domain feeds
3. The domain's resolved IPs against IP/CIDR feeds

## Integration Patterns

### Pattern 1: Simple Approval Flow

```go
func validateSignup(email string) error {
    result, err := checkEmail(email)
    if err != nil {
        return err
    }

    switch result.Recommendation {
    case "approve":
        return nil  // Allow signup
    case "review":
        return flagForReview(email, result)  // Manual review
    case "reject":
        return errors.New("signup blocked due to security concerns")
    }
}
```

### Pattern 2: Flag-Based Decisions

```go
func validateSignup(email string) error {
    result, err := checkEmail(email)
    if err != nil {
        return err
    }

    // Block specific categories
    if result.Flags.IsDisposableEmail {
        return errors.New("disposable email addresses not allowed")
    }

    if result.Flags.IsC2 || result.Flags.IsPhishing {
        return errors.New("signup blocked due to security concerns")
    }

    // Review medium risk
    if result.RiskLevel == "medium" || result.RiskLevel == "high" {
        return flagForReview(email, result)
    }

    return nil
}
```

### Pattern 3: Score-Based with Thresholds

```go
func validateSignup(email string) error {
    result, err := checkEmail(email)
    if err != nil {
        return err
    }

    // Custom thresholds
    if result.Score >= 60 {
        return errors.New("signup rejected")
    }

    if result.Score >= 30 {
        return flagForReview(email, result)
    }

    return nil  // Auto-approve
}
```

## Setup

Before using the scoring API, threat intelligence feeds must be hydrated:

```bash
# Start the service
task service:start
task service:wait

# Hydrate threat intelligence (takes several minutes)
curl -X POST http://localhost:8080/api/intel/hydrate

# Or use the task command
task call:intel-hydrate
```

## Configuration

Control which feeds are downloaded by editing `config/feed_config.json`. Current configuration includes 105 feeds covering:

- Phishing domains
- Disposable email services
- Malicious IPs
- C2 infrastructure
- Tor/VPN/Proxy networks
- Spam sources
- Botnet activity

## Error Handling

```json
{
  "success": false,
  "error": "threat intelligence feeds have not been hydrated"
}
```

Common errors:
- **Feeds not hydrated**: Run hydration endpoint first
- **Invalid request**: Email or domain required
- **Service unavailable**: Intel manager not configured

## Testing

Use the provided test script:

```bash
chmod +x scripts/test_scoring.sh
./scripts/test_scoring.sh
```

Or test manually:

```bash
# Test with domain
curl -s -X POST http://localhost:8080/api/intel/check \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}' | jq .data

# Test with email
curl -s -X POST http://localhost:8080/api/intel/check \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}' | jq .data
```

## Performance

- **Latency**: Typically <100ms for scoring requests
- **Feed Hydration**: Takes 5-15 minutes, should be run periodically (e.g., daily)
- **Memory**: ~500MB-1GB for hydrated feed data
- **Concurrency**: Thread-safe, supports multiple concurrent requests

## Best Practices

1. **Hydrate feeds regularly**: Run hydration daily or weekly to keep feeds current
2. **Use appropriate thresholds**: Tune recommendation thresholds based on your risk tolerance
3. **Combine with other signals**: Use Sleuth scores alongside other fraud detection signals
4. **Log and monitor**: Track score distributions and false positives
5. **Review edge cases**: Manually review medium/high risk signups
6. **Cache results**: Consider caching domain scores for frequently seen domains
