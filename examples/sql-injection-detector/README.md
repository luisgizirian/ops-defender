# SQL Injection Detector - Pattern Analyzer Example

This example demonstrates how to implement a custom `PatternAnalyzer` extension for Ops Defender to detect SQL injection attempts during deferred analysis.

## Overview

The `SQLInjectionDetector` analyzes request patterns from an IP address and identifies common SQL injection attack signatures, including:

- **UNION-based injection** (`UNION SELECT`, `UNION ALL SELECT`)
- **SQL keyword abuse** (`SELECT...FROM`, `INSERT INTO`, `DELETE FROM`, `DROP TABLE`)
- **Stored procedure execution** (`EXEC sp_`, `xp_cmdshell`)
- **SQL comments** (`--`, `#`, `/*`, `*/`)
- **Quote-based injection** (`' OR '1'='1`)
- **Always-true conditions** (`1=1`, `'='`)
- **Known test strings** (`admin'--`, `' OR 1=1--`)

## How It Works

1. **Deferred Analysis**: Runs asynchronously after an IP reaches the analysis threshold (default: 5 requests)
2. **Pattern Matching**: Uses regex patterns to detect SQL injection signatures
3. **URL Decoding**: Decodes URIs to catch encoded attack patterns
4. **Confidence Scoring**: Assigns confidence scores (0.0-1.0) based on pattern specificity
5. **Threshold Blocking**: Blocks IPs when confidence ≥ 0.75

## Confidence Scoring

Different patterns have different base confidence scores:

| Pattern Type | Base Confidence | Rationale |
|--------------|-----------------|-----------|
| UNION-based injection | 0.95 | Very specific, rarely legitimate |
| Stored procedures | 0.95 | Very specific attack vector |
| Known test strings | 0.98 | Explicit attack attempt |
| Quote-based injection | 0.90 | High specificity |
| SQL keywords | 0.85 | Moderately specific |
| Always-true conditions | 0.85 | High specificity |
| SQL comments | 0.70 | Can be legitimate in some contexts |

**Confidence boosting**: If multiple suspicious indicators are present in the same URI, confidence increases by 5% per additional indicator (capped at 0.99).

## Usage

### Integration with Ops Defender

```go
package main

import (
    "github.com/ops/defender/internal/defender"
    "github.com/ops/defender/examples/sql-injection-detector"
)

func main() {
    // Create defender instance
    d := defender.NewDefender(defender.DefenderOptions{
        // ... options ...
    })

    // Register SQL injection detector
    sqlDetector := sql_injection_detector.NewSQLInjectionDetector()
    d.RegisterPatternAnalyzer(sqlDetector)

    // Start defender
    // ...
}
```

### Testing

```bash
# Send legitimate request
curl -H "X-Real-IP: 10.0.0.1" \
     -H "X-Original-URI: /api/users?id=123" \
     http://localhost:8080/check

# Send SQL injection attempt (repeat 5 times to trigger analysis)
for i in {1..5}; do
  curl -H "X-Real-IP: 10.0.0.2" \
       -H "X-Original-URI: /api/users?id=1' OR '1'='1" \
       http://localhost:8080/check
done

# Check if IP was blocked
curl http://localhost:8080/stats | jq '.blocked_ips'
```

Expected log output:
```
Request pattern flagged by analyzer 'sql-injection-detector': IP=10.0.0.2, Reason=SQL injection pattern detected: Quote-based injection, URI=/api/users?id=1' OR '1'='1, Confidence=0.95
IP marked as suspicious and blocked: 10.0.0.2 (reason: SQL injection pattern detected: Quote-based injection, pattern: /api/users?id=1' OR '1'='1, expires: 2026-01-21T15:30:00Z)
```

## Priority System

The detector is configured with **priority 10** (high priority), meaning it runs early in the analysis phase:

- **0-10**: Critical checks (run first)
- **11-50**: Standard checks
- **51-100**: Exploratory checks (run last)

This ensures SQL injection detection happens before less specific pattern checks.

## Customization

### Adjust Confidence Threshold

Modify the threshold in `AnalyzePattern()`:

```go
// More strict (fewer false positives, more false negatives)
if highestConfidence >= 0.90 {
    return extensions.AnalysisResult{IsSuspicious: true, ...}
}

// More lenient (more false positives, fewer false negatives)
if highestConfidence >= 0.60 {
    return extensions.AnalysisResult{IsSuspicious: true, ...}
}
```

### Add Custom Patterns

Add new regex patterns to the `patterns` slice:

```go
patterns: []*regexp.Regexp{
    // ... existing patterns ...
    regexp.MustCompile(`(?i)(waitfor\s+delay|benchmark\()`), // Time-based injection
}
```

### Change Priority

Adjust the priority value (0-100):

```go
priority: 50, // Standard priority (middle of the queue)
```

## Performance Considerations

- **Execution time**: ~500μs per analysis (7 regex patterns, URL decoding)
- **No blocking I/O**: All pattern matching is in-memory
- **Early exit**: Stops checking when confidence ≥ 0.95
- **Async execution**: Runs in analysis worker, not on request path

## Error Handling

The analyzer uses fail-open behavior:
- URL decoding errors → uses original URI
- Pattern matching errors → logged, analysis continues
- Analyzer panics → caught by defender, other analyzers still run

## Metrics

Once integrated, metrics are available at `/metrics`:

```
# HELP ops_defender_blocked_requests_total Total number of blocked requests
# TYPE ops_defender_blocked_requests_total counter
ops_defender_blocked_requests_total{reason="SQL injection pattern detected: UNION-based injection"} 15
ops_defender_blocked_requests_total{reason="SQL injection pattern detected: Quote-based injection"} 8
```

## Security Notes

⚠️ **False Positives**: Some legitimate use cases might trigger SQL detection (e.g., documentation sites discussing SQL). Consider:
- Whitelisting known good IPs
- Adjusting confidence thresholds
- Adding exception patterns

⚠️ **Evasion**: Sophisticated attackers may use encoding, obfuscation, or unusual patterns. This detector catches common attacks but is not exhaustive.

⚠️ **Performance**: Regex matching can be expensive. For production, consider:
- Pre-compiling patterns (already done)
- Limiting URI length before analysis
- Using more efficient string matching for simple patterns

## License

Same as Ops Defender (see LICENSE file in repository root).
