# PostHandler Extension Example

This example demonstrates the **RequestPostHandler** extension point, which allows you to override block/allow decisions **after** all core processing completes but **before** the HTTP response is sent.

## What This Example Shows

Two PostHandler implementations:

1. **EmergencyAllowlist** - Allows critical IPs even when they're blocked by core system
2. **HealthCheckOverride** - Allows health check endpoints even when requesting IP is blocked

## Use Cases

PostHandlers are ideal for:

- **Emergency access** - Allow critical IPs during incidents
- **Health checks** - Ensure monitoring can always check service status
- **Maintenance windows** - Temporary overrides during deployments
- **Path-based exceptions** - Allow specific endpoints regardless of IP reputation
- **Final security layers** - Add extra blocking criteria after core checks

## Running the Example

```bash
# Build and run
cd examples/posthandler-example
go run main.go
```

The server starts on port 8080 with two PostHandlers registered.

## Testing

### Test 1: Emergency IP Override (Block → Allow)

```bash
# First, block IP 10.0.0.1 by sending malicious requests
for i in {1..5}; do
  curl -H "X-Real-IP: 10.0.0.1" \
       -H "X-Original-URI: /../etc/passwd" \
       http://localhost:8080/check
done

# IP is now blocked. But emergency allowlist will override:
curl -v -H "X-Real-IP: 10.0.0.1" \
        -H "X-Original-URI: /api/users" \
        http://localhost:8080/check

# Expected: HTTP 200 (allowed due to emergency override)
# Log: "Request decision overridden by post-handler 'emergency-allowlist': 
#       IP=10.0.0.1, URI=/api/users, ShouldBlock=false, 
#       Reason=critical IP emergency override"
```

### Test 2: Health Check Path Override (Block → Allow)

```bash
# Block IP 192.168.1.100
for i in {1..5}; do
  curl -H "X-Real-IP: 192.168.1.100" \
       -H "X-Original-URI: /../../etc/passwd" \
       http://localhost:8080/check
done

# IP is blocked. But health check path will override:
curl -v -H "X-Real-IP: 192.168.1.100" \
        -H "X-Original-URI: /health" \
        http://localhost:8080/check

# Expected: HTTP 200 (allowed due to health check override)
# Log: "Request decision overridden by post-handler 'health-check-override': 
#       IP=192.168.1.100, URI=/health, ShouldBlock=false, 
#       Reason=health check endpoint override"
```

### Test 3: Normal Request (No Override)

```bash
# Normal request from non-critical IP
curl -v -H "X-Real-IP: 1.2.3.4" \
        -H "X-Original-URI: /api/users" \
        http://localhost:8080/check

# Expected: HTTP 200 (allowed by core system, no override needed)
```

### Test 4: Blocked Request (No Override)

```bash
# Block IP 5.6.7.8
for i in {1..5}; do
  curl -H "X-Real-IP: 5.6.7.8" \
       -H "X-Original-URI: /../etc/passwd" \
       http://localhost:8080/check
done

# Request from blocked IP to non-health path
curl -v -H "X-Real-IP: 5.6.7.8" \
        -H "X-Original-URI: /api/users" \
        http://localhost:8080/check

# Expected: HTTP 403 (blocked, no override)
```

## How It Works

### Execution Flow

1. Request arrives at `/check` endpoint
2. Core system processes request (pattern matching, blocking checks)
3. Core system decides: allow or block
4. **PostHandlers invoked** in registration order
5. If PostHandler returns `ShouldOverride=true`:
   - Override core decision
   - Use PostHandler's `ShouldBlock` value
6. Write HTTP response (200 or 403)

### Code Walkthrough

**EmergencyAllowlist PostHandler:**

```go
func (e *EmergencyAllowlist) PostHandleRequest(ctx extensions.PostHandlerContext) (extensions.PostHandlerResult, error) {
    // Check if request was blocked AND IP is in critical list
    if ctx.WasBlocked && e.criticalIPs[ctx.Request.IP] {
        return extensions.PostHandlerResult{
            ShouldOverride: true,  // Override core decision
            ShouldBlock:    false, // Change block to allow
            Reason:         "critical IP emergency override",
        }, nil
    }
    
    // Don't override - use core system's decision
    return extensions.PostHandlerResult{ShouldOverride: false}, nil
}
```

**Context Fields Available:**

- `Request.IP` - Client IP address
- `Request.URI` - Requested URI
- `Request.UserAgent` - User-Agent header
- `Request.Headers` - All HTTP headers
- `Request.Method` - HTTP method
- `WasBlocked` - True if core system decided to block
- `BlockReason` - Reason for blocking (if blocked)
- `WasBypassedByPreHandler` - True if bypassed by pre-handler

## Security Considerations

⚠️ **Use PostHandlers Carefully:**

- Overriding security decisions should be **rare**
- Use **narrow matching** (specific IPs/paths)
- **Log all overrides** for audit trail
- Review PostHandler code carefully before production
- Consider rate limiting override usage

## Integration with Ops Defender

To integrate these PostHandlers into your Ops Defender deployment:

```go
import (
    "github.com/ops/defender/pkg/defender"
    "yourorg/emergencyaccess"
    "yourorg/healthcheck"
)

func main() {
    d := defender.NewDefender(opts)
    
    // Register your custom PostHandlers
    d.RegisterPostHandler(emergencyaccess.NewEmergencyAllowlist(criticalIPs))
    d.RegisterPostHandler(healthcheck.NewHealthCheckOverride(healthPaths))
    
    // ... rest of server setup
}
```

## Extension System Overview

Ops Defender provides four extension points:

1. **PreHandler** - Before core processing (bypass all checks)
2. **PatternAnalyzer** - During analysis (custom pattern detection)
3. **PostHandler** - After processing (override final decision) ← This example
4. **StatsDataProvider** - Expose custom data in all informational endpoints

See main [README.md](../../README.md) for complete extension system documentation.

## Additional Resources

- [Extension System Guide](../../README.md#extension-system)
- [PreHandler Example](../external-extension/)
- [PatternAnalyzer Example](../sql-injection-detector/)
- [StatsDataProvider Example](../stats-provider-example/)
- [Development Guide](../../.github/copilot-instructions.md)
