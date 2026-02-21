# StatsDataProvider Extension Example

This example demonstrates the **StatsDataProvider** extension point, which lets extensions contribute custom data to **all** Ops Defender informational endpoints — `/stats`, `/report`, `/timeseries`, `/metrics`, and `/events` — without creating per-extension routes.

## What This Example Shows

Two `StatsDataProvider` implementations that are each dual-registered (also as a PreHandler and a PostHandler respectively):

| Extension | Roles | What It Tracks |
|-----------|-------|----------------|
| `RequestRateTracker` | PreHandler + StatsDataProvider | Per-URI-prefix request counts |
| `BlockedIPAuditStats` | PostHandler + StatsDataProvider | Total blocks/allows + last blocked IP |

> **Key insight:** A single struct can implement multiple extension interfaces and be registered for each role independently. This example deliberately combines roles to show a realistic pattern — an extension that both *acts* on requests and *exposes* its own data.

## Running the Example

```bash
cd examples/stats-provider-example
go run main.go
```

The server starts on port 8080 with both providers registered.

## Testing

### Step 1 – Send Some Requests

```bash
# A handful of normal requests across different paths
curl -H "X-Real-IP: 10.0.0.1" -H "X-Original-URI: /api/users"    http://localhost:8080/check
curl -H "X-Real-IP: 10.0.0.2" -H "X-Original-URI: /api/products" http://localhost:8080/check
curl -H "X-Real-IP: 10.0.0.3" -H "X-Original-URI: /admin/panel"  http://localhost:8080/check
curl -H "X-Real-IP: 10.0.0.1" -H "X-Original-URI: /api/users"    http://localhost:8080/check
```

### Step 2 – Trigger a Block

```bash
# Repeat a suspicious path 5 times to hit the analysis threshold
for i in {1..5}; do
  curl -H "X-Real-IP: 10.0.0.9" \
       -H "X-Original-URI: /../etc/passwd" \
       http://localhost:8080/check
done
# Wait a moment for deferred analysis to run, then:
sleep 1
curl -H "X-Real-IP: 10.0.0.9" -H "X-Original-URI: /any" http://localhost:8080/check
# Expected: HTTP 403
```

### Step 3 – Query Informational Endpoints

#### `/stats` — JSON with `extensions` field

```bash
curl http://localhost:8080/stats | jq .extensions
```

Expected response (values will vary):

```json
{
  "audit-stats": {
    "last_blocked_ip": "10.0.0.9",
    "total_allows": 5,
    "total_blocks": 1
  },
  "request-rate-tracker": {
    "api": 3,
    "admin": 1,
    "root": 1
  }
}
```

#### `/report` — Same `extensions` field on report

```bash
curl "http://localhost:8080/report?period=1" | jq .extensions
```

Expected output: same structure as `/stats`.

#### `/timeseries` — Same `extensions` field on time-series

```bash
curl "http://localhost:8080/timeseries?period=1&interval=5m" | jq .extensions
```

#### `/metrics` — Prometheus gauges for numeric values

```bash
curl http://localhost:8080/metrics | grep ops_defender_extension
```

Expected output:

```text
# HELP ops_defender_extension_audit_stats_total_blocks Extension metric from audit-stats
# TYPE ops_defender_extension_audit_stats_total_blocks gauge
ops_defender_extension_audit_stats_total_blocks 1

# HELP ops_defender_extension_audit_stats_total_allows Extension metric from audit-stats
# TYPE ops_defender_extension_audit_stats_total_allows gauge
ops_defender_extension_audit_stats_total_allows 5

# HELP ops_defender_extension_request_rate_tracker_api Extension metric from request-rate-tracker
# TYPE ops_defender_extension_request_rate_tracker_api gauge
ops_defender_extension_request_rate_tracker_api 3
```

> **Note:** String values (`last_blocked_ip`) are automatically skipped in Prometheus output but still appear in the JSON endpoints.

#### `/events` — Real-time SSE stream

```bash
curl -N http://localhost:8080/events
```

Every 2 seconds you will see a `stats_update` event that includes the `extensions` field:

```
data: {"type":"stats_update","timestamp":"...","data":{"active_ips":1,"blocked_ips":1,"blocked_requests":1,"dropped_ips":0,"extensions":{"audit-stats":{"last_blocked_ip":"10.0.0.9","total_allows":5,"total_blocks":1},"request-rate-tracker":{"api":3,"admin":1}},"total_requests":6}}
```

## How It Works

### Interface

```go
type StatsDataProvider interface {
    // GetStats returns custom key-value data included in all informational responses.
    // Numeric values are also emitted as Prometheus gauges in /metrics.
    // Called on the response path — keep it fast.
    GetStats() (map[string]interface{}, error)

    // Name is used as the namespace key in the "extensions" object.
    Name() string
}
```

### Registration

```go
// Register the provider once; it appears in all informational endpoints.
d.RegisterStatsProvider(myProvider)
```

### Response Structure

All JSON informational endpoints include an `"extensions"` object keyed by provider name. The field is omitted (`omitempty`) when no providers are registered, so existing consumers are not affected.

```
/stats, /report, /timeseries
└── "extensions"
    ├── "<provider-name-1>"  → map[string]interface{}
    └── "<provider-name-2>"  → map[string]interface{}
```

For `/metrics`, numeric fields are emitted as Prometheus gauges:

```
ops_defender_extension_<provider>_<key>  <numeric_value>
```

Provider names and keys are auto-sanitized for Prometheus (hyphens/spaces → underscores, lowercased).

### Combining Roles (Dual-Registration Pattern)

A struct can implement multiple extension interfaces and be registered for each:

```go
// RequestRateTracker acts as both a PreHandler and a StatsDataProvider.
type RequestRateTracker struct { ... }
func (t *RequestRateTracker) Name() string                                              { ... }
func (t *RequestRateTracker) PreHandleRequest(req extensions.RequestInfo) (...)        { ... }
func (t *RequestRateTracker) GetStats() (map[string]interface{}, error)                { ... }

// Register for both roles:
d.RegisterExtension(rateTracker)     // PreHandler: called on every /check request
d.RegisterStatsProvider(rateTracker) // StatsDataProvider: called on every stats/events request
```

### Error Handling

If `GetStats()` returns an error, that provider's data is omitted from the response. All other providers continue (fail-open). The error is logged:

```
StatsDataProvider 'my-provider' returned error, skipping: <error message>
```

### Thread Safety

`GetStats()` may be called concurrently with request handling. Use a `sync.RWMutex` or `sync/atomic` for counters, as shown in this example:

```go
// Fast path with atomic for hot counters
func (a *BlockedIPAuditStats) PostHandleRequest(...) (...) {
    atomic.AddInt64(&a.totalBlocks, 1)
    ...
}

// Read path acquires read lock
func (a *BlockedIPAuditStats) GetStats() (...) {
    return map[string]interface{}{
        "total_blocks": atomic.LoadInt64(&a.totalBlocks),
    }, nil
}
```

## Performance Considerations

- `GetStats()` runs on the **response path** — keep it O(1) or O(small constant)
- Use **pre-computed/cached values** rather than aggregating on the fly
- Avoid blocking I/O (no database calls, no external HTTP requests)
- The `/events` endpoint calls `GetStats()` every 2 seconds per connected client

## Security Considerations

⚠️ `GetStats()` output appears in HTTP responses. Be careful:
- **Do not expose secrets** (API keys, internal IPs, auth tokens)
- **Sanitize string values** before returning them
- **Limit array/map sizes** to avoid unbounded memory growth in the response

## Extension System Overview

Ops Defender provides four extension points:

1. **PreHandler** — Before core processing (bypass all checks)
2. **PatternAnalyzer** — During deferred analysis (custom pattern detection)
3. **PostHandler** — After processing (override final decision)
4. **StatsDataProvider** — Expose custom data in all informational endpoints ← *This example*

See main [README.md](../../README.md#extension-system) for complete documentation.

## Additional Resources

- [Extension System Guide](../../README.md#extension-system)
- [PreHandler Example](../external-extension/)
- [PatternAnalyzer Example](../sql-injection-detector/)
- [PostHandler Example](../posthandler-example/)
