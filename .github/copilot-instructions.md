# Ops Defender - AI Coding Agent Instructions

> **🤖 PROJECT GENESIS:**  
> This project was created as an experiment using GitHub Copilot as the primary development tool. While it includes comprehensive testing and documentation, it's experimental software. All contributors must maintain the experimental notices in README.md and DEPLOYMENT.md to ensure users understand the risks before production deployment.

## Mandatory Requirements

### Documentation Updates
**CRITICAL - ALWAYS REQUIRED:**
When making ANY code changes, configuration changes, or adding new features, you **MUST** update the relevant documentation:

1. **Update README.md** if:
   - Adding new features or capabilities
   - Changing configuration options or environment variables
   - Modifying API endpoints or behavior
   - Adding new dependencies or requirements
   - Changing deployment procedures

2. **Update relevant .md files** (DEPLOYMENT.md, DDOS-DEFENSE.md, ROLLBACK.md, etc.) if:
   - Changing deployment processes
   - Modifying security features or attack detection
   - Altering rollback procedures

3. **Update copilot-instructions.md** (this file) if:
   - Changing architectural patterns or design principles
   - Adding new conventions or best practices
   - Modifying file structure or responsibilities

4. **Update code comments** if:
   - Changing complex algorithms or logic
   - Adding new critical code paths

**No exceptions:** Documentation must be kept in sync with code changes. Outdated documentation is worse than no documentation.

## Project Overview

Ops Defender is a high-performance **HTTP-based** request monitoring service designed to integrate with **any reverse proxy or API gateway** via a standard HTTP validation endpoint. It uses **deferred (asynchronous) analysis** to avoid impacting legitimate traffic performance.

**Core Architecture:** Proxy (Nginx/Caddy/Traefik/HAProxy/etc.) → Ops Defender `/check` endpoint → Pattern Analysis → Block Decision

**HTTP-Based Design:** The `/check` endpoint accepts HTTP requests with `X-Real-IP` and `X-Original-URI` headers, returning 200 (allow) or 403 (block). This simple HTTP API makes it compatible with any proxy that can:
1. Forward requests to an HTTP endpoint
2. Make routing decisions based on HTTP status codes
3. Pass client IP and URI as headers

**IPv4 and IPv6 Support:** Ops Defender fully supports both IPv4 and IPv6 addresses. The `extractIP()` function uses Go's `net.SplitHostPort()` to correctly parse both address formats from headers (X-Real-IP, X-Forwarded-For) and RemoteAddr.

**Key Design Principle:** First N requests (default 5) from any IP are always allowed through for analysis, then suspicious IPs are blocked for configured duration (default 24 hours).

## Critical Architecture Concepts

### Extension System

Ops Defender provides a **RequestPreHandler** extensibility point for intercepting requests before core processing:

**Architecture:**
- **Interface**: `internal/extensions/extensions.go` - Defines `RequestPreHandler` interface
- **Registration**: `Defender.RegisterExtension()` - Thread-safe registration method
- **Invocation**: First code executed in `CheckRequest()`, before any tracking or analysis

**Execution Flow:**
```go
// In CheckRequest():
1. Extract IP/URI from request
2. INVOKE PRE-HANDLERS (extension point) ← NEW
3. If extension returns ShouldBypass=true → return 200, skip all processing
4. Otherwise: Continue with normal flow (blocking checks, analysis, etc.)
```

**Key Design Principles:**
- **Zero core modifications** - Extensions are external packages
- **Fail-open** - Extension errors don't block requests
- **Performance-first** - Minimal lock contention, optimized execution path
- **Ordered execution** - Handlers run in registration order
- **Bypass before tracking** - Bypassed requests don't appear in any metrics

**When to Use:**
- Custom filtering logic (e.g., allowlists) that should bypass ALL core checks
- Application-specific request preprocessing
- Integration with external authorization systems

**When NOT to Use:**
- Modifying core blocking behavior (use pattern configuration instead)
- Adding new attack pattern detection (add to `suspiciousPatterns` in defender.go)
- Metrics/logging only (use telemetry or events instead)

**Implementation Guidelines:**
- Keep `PreHandleRequest()` **fast** - runs on critical request path
- Avoid blocking I/O or expensive computation
- Use in-memory data structures (maps, caches)
- Handle errors gracefully (fail-open behavior)
- Thread-safe: method may be called concurrently

**Example Extension:**
```go
type CustomFilter struct {
    excludedIPs map[string]bool
}

func (f *CustomFilter) PreHandleRequest(req extensions.RequestInfo) (extensions.PreHandlerResult, error) {
    if f.excludedIPs[req.IP] {
        return extensions.PreHandlerResult{
            ShouldBypass: true,
            Reason:       "custom exclusion",
        }, nil
    }
    return extensions.PreHandlerResult{ShouldBypass: false}, nil
}

func (f *CustomFilter) Name() string { return "custom-filter" }
```

**Adding New Extensions:**
1. Create extension package (separate repo or `internal/extensions/<name>`)
2. Implement `RequestPreHandler` interface
3. Register in `main.go`: `defender.RegisterExtension(extension)`
4. Unit test extension logic independently
5. Integration test with Ops Defender (use multi-root workspace)

**Observability:**
- Registration: `Registered extension: <name> (total extensions: N)`
- Errors: `Extension '<name>' returned error, continuing: <error>`
- Bypass: `Request bypassed by extension '<name>': IP=..., URI=..., Reason=...`

**Security Notes:**
- Extensions run with full Ops Defender privileges
- Bypassed requests skip ALL security checks (including blocking)
- Review extension code carefully before production deployment
- Use strict matching, avoid broad bypass rules

### PostHandler Extension System

Ops Defender provides a **RequestPostHandler** extensibility point for intercepting requests after core processing but before the final HTTP response is sent:

**Architecture:**
- **Interface**: `pkg/extensions/extensions.go` - Defines `RequestPostHandler` interface
- **Registration**: `Defender.RegisterPostHandler()` - Thread-safe registration method
- **Invocation**: Last code executed in `CheckRequest()`, after all blocking checks but before HTTP response

**Execution Flow:**
```go
// In CheckRequest():
1. Extract IP/URI from request
2. Invoke pre-handlers (if any)
3. Execute core blocking logic (cache checks, pattern analysis)
4. Log request for deferred analysis
5. INVOKE POST-HANDLERS (extension point) ← NEW
6. If extension returns ShouldOverride=true → use extension's block/allow decision
7. Otherwise: Use core system's decision
8. Write final HTTP response (200 or 403)
```

**Key Design Principles:**
- **Complete request flow coverage** - Post-handlers see the full processing result
- **Fail-open** - Extension errors don't block requests
- **Override capability** - Can reverse core system's block/allow decision
- **Ordered execution** - Handlers run in registration order, first override wins
- **Context-aware** - Post-handlers receive full processing context

**PostHandlerContext Fields:**
- `Request` - Original request info (IP, URI, headers, method)
- `WasBlocked` - True if core system decided to block
- `BlockReason` - Reason for blocking (if WasBlocked is true)
- `WasBypassedByPreHandler` - True if request was bypassed by a pre-handler

**When to Use:**
- Override blocking decisions for specific paths (e.g., health checks, admin endpoints)
- Custom allow/block logic based on complete request processing result
- Integration with external decision systems (after seeing core system's verdict)
- Temporary emergency overrides (allow critical IPs even when blocked)

**When NOT to Use:**
- Early request filtering (use PreHandler instead)
- Pattern detection during analysis (use PatternAnalyzer instead)
- Metrics/logging only (use telemetry or events instead)

**Implementation Guidelines:**
- Keep `PostHandleRequest()` **fast** - runs on critical response path
- Avoid blocking I/O or expensive computation
- Use in-memory lookups (maps, caches)
- Handle errors gracefully (fail-open behavior)
- Thread-safe: method may be called concurrently
- Be conservative with overrides - reversing core decisions should be rare

**Example Extension:**
```go
type EmergencyAllowlist struct {
    criticalIPs map[string]bool
}

func (e *EmergencyAllowlist) PostHandleRequest(ctx extensions.PostHandlerContext) (extensions.PostHandlerResult, error) {
    // Allow critical IPs even if they were blocked
    if ctx.WasBlocked && e.criticalIPs[ctx.Request.IP] {
        return extensions.PostHandlerResult{
            ShouldOverride: true,
            ShouldBlock:    false, // Override to allow
            Reason:         "critical IP allowlist",
        }, nil
    }
    return extensions.PostHandlerResult{ShouldOverride: false}, nil
}

func (e *EmergencyAllowlist) Name() string { return "emergency-allowlist" }
```

**Another Example - Path-Based Override:**
```go
type HealthCheckOverride struct {
    healthPaths map[string]bool
}

func (h *HealthCheckOverride) PostHandleRequest(ctx extensions.PostHandlerContext) (extensions.PostHandlerResult, error) {
    // Always allow health check endpoints even if IP is blocked
    if ctx.WasBlocked && h.healthPaths[ctx.Request.URI] {
        return extensions.PostHandlerResult{
            ShouldOverride: true,
            ShouldBlock:    false,
            Reason:         "health check endpoint override",
        }, nil
    }
    return extensions.PostHandlerResult{ShouldOverride: false}, nil
}

func (h *HealthCheckOverride) Name() string { return "health-check-override" }
```

**Adding New PostHandlers:**
1. Create extension package (separate repo or `pkg/extensions/<name>`)
2. Implement `RequestPostHandler` interface
3. Register in `main.go`: `defender.RegisterPostHandler(handler)`
4. Unit test handler logic independently
5. Integration test with Ops Defender

**Observability:**
- Registration: `Registered post-handler: <name> (total post-handlers: N)`
- Errors: `PostHandler '<name>' returned error, continuing: <error>`
- Override: `Request decision overridden by post-handler '<name>': IP=..., URI=..., ShouldBlock=..., Reason=...`

**Security Notes:**
- Post-handlers can reverse security decisions - use with extreme caution
- Overrides should be narrow and well-justified (specific IPs/paths)
- Log all overrides for security audit trails
- Review post-handler code carefully before production deployment
- Consider rate limiting override usage to prevent abuse

**Extension System Summary:**

Ops Defender provides **three extension points** covering the complete request lifecycle:

1. **PreHandler** - Before core processing (bypass all checks)
2. **PatternAnalyzer** - During deferred analysis (custom pattern detection)
3. **PostHandler** - After core processing (override final decision)

This three-tier system allows complete customization without modifying core code.

### Three-Tier Caching System

Ops Defender uses layered caching to minimize latency and Redis calls:

1. **Tier 1 - Blocked Cache (in-memory):** `blockedCache map[string]time.Time` - Fastest path, ~100ns lookup for blocked IPs
2. **Tier 2 - Active Tracking (in-memory):** `ipTrackers map[string]*IPTracker` - Tracks IPs currently being analyzed
3. **Tier 3 - Redis Storage (persistent):** Fallback for unknown IPs, provides distributed state across instances

**Request Flow Example:**
- Blocked IP: Check Tier 1 cache → instant 403 (no Redis call)
- New IP: Miss all tiers → query Redis → create tracker → allow through
- Active IP: Skip Tier 1 → found in Tier 2 → log request → allow through

### Deferred Analysis Pattern

**CRITICAL:** Analysis happens asynchronously to avoid blocking legitimate traffic. **EXCEPT for excessive nesting attacks which use immediate pre-logging blocking:**

```go
// IMMEDIATE CHECK: Block excessive nesting BEFORE logging (unforgiving)
if d.hasExcessiveNestingFast(uri) {
    // Block immediately - first request never reaches backend
    d.blockedCache[ip] = time.Now().Add(d.blockDuration)
    w.WriteHeader(http.StatusForbidden)
    return
}

// DEFERRED ANALYSIS: For other patterns, log and analyze asynchronously
tracker.RequestLogs = append(tracker.RequestLogs, RequestLog{...})
w.WriteHeader(http.StatusOK)  // Non-blocking response

// Separately: Queue for analysis after threshold
if requestCount >= d.analysisThreshold {
    d.analysisChan <- ip  // Async channel
}

// Background worker analyzes patterns
go d.analysisWorker()
```

**Two-Tier Detection System:**
1. **Immediate Blocking (Pre-Logging):** Excessive URL-encoded nesting attacks
   - Checked BEFORE request logging
   - First malicious request is blocked (prevents backend crashes)
   - Uses optimized string matching (~150-1150ns)
2. **Deferred Analysis (Post-Logging):** All other attack patterns
   - Logged first, analyzed asynchronously
   - First ~5 requests allowed through for analysis
   - Zero performance impact on legitimate traffic

Never add blocking I/O or heavy computation to `CheckRequest()` except for immediate pre-logging checks which must be highly optimized.

### Fail-Open Redis Error Handling

**CRITICAL:** Redis connectivity errors result in fail-open behavior (allow requests) rather than HTTP 500 errors:

**Design Principle:** When Redis/storage is unavailable, **allow traffic through** rather than blocking all requests. This prioritizes availability over perfect security during infrastructure issues.

**Implementation:**
```go
// CheckRequest: Redis error allows request through
blocked, err := d.storage.IsBlocked(ctx, ip)
if err != nil {
    // Fail-open: Allow request through, don't return 500
    log.Printf("WARNING: Redis error, allowing request: %v", err)
    blocked = false
}

// MetricsHandler: Redis error returns partial data (not 500)
blockedIPs, err := d.storage.GetBlockedIPs(ctx)
if err != nil {
    // Continue with empty data instead of returning 500
    log.Printf("WARNING: Redis error, continuing with partial data: %v", err)
    blockedIPs = []storage.BlockedIPInfo{}
}
```

**Affected Endpoints:**
- `/check` - Always returns 200 (allow) on Redis errors
- `/metrics` - Returns partial metrics with zero blocked IPs
- `/timeseries` - Returns partial time-series with empty event history
- `/stats` - Returns stats with empty blocked IP list
- `/report` - Returns report with empty block events

**Why Fail-Open:**
1. **Availability over security:** Better to allow some malicious traffic temporarily than block all legitimate traffic
2. **Redis is optional:** System can operate (degraded) without Redis using in-memory caching
3. **Testing flexibility:** Allows testing without Redis infrastructure
4. **Operational resilience:** Service continues during Redis maintenance/failures

**When NOT to use fail-open:** If your threat model requires hard blocking (e.g., protecting highly sensitive endpoints), consider changing fail-open to fail-closed and ensuring Redis HA.

### IP Promotion/Demotion Mechanics

**How Blocked IPs Stay in Tier 1 Cache Without Demotion:**

Once an IP is blocked and added to `blockedCache` (Tier 1), it **never gets demoted** back to Redis during its block period. Here's the complete lifecycle:

**1. IP Gets Blocked:**
```go
// In analyzeIP() when suspicious pattern detected:
d.blockedCache[ip] = time.Now().Add(d.blockDuration)  // Added to Tier 1
d.storage.BlockIP(ctx, ip, reason, d.blockDuration)   // Also stored in Redis
```

**2. Subsequent Requests from Blocked IP:**
```go
// In CheckRequest() - Line 109-118:
if expiresAt, blocked := d.blockedCache[ip]; blocked {
    if time.Now().Before(expiresAt) {
        // Still valid - return 403 immediately
        // IP STAYS IN CACHE - no demotion!
        w.WriteHeader(http.StatusForbidden)
        return
    }
    // Only removed if expired
    delete(d.blockedCache, ip)
}
```

**Key Points:**
- **No LRU on blockedCache**: Unlike `ipTrackers`, blocked IPs are never evicted due to memory pressure
- **No demotion logic**: There's no code path that removes a valid (non-expired) blocked IP from cache
- **Expiry is the only removal**: IPs are removed from `blockedCache` only when:
  - Time-based expiry check finds `time.Now().After(expiresAt)` (line 112)
  - Background cleanup worker runs every 5 minutes (line 348-351)
- **Repeated requests don't trigger Redis**: Once cached, all subsequent blocked IP checks are pure memory lookups (~100ns)

**Why This Design is Optimal:**
1. **Performance**: Blocked IPs (often attackers retrying) get the fastest possible rejection
2. **Redis efficiency**: No repeated Redis calls for the same blocked IP
3. **Memory safety**: Blocked IPs use minimal memory (~40 bytes each)
4. **Deterministic**: Block duration is guaranteed - no early eviction

**What Happens When Block Expires:**
```go
// After blockDuration (default 60 minutes):
if time.Now().After(expiresAt) {
    delete(d.blockedCache, ip)  // Removed from Tier 1
}
// Next request from this IP:
// - Not in blockedCache → proceeds to check Redis (Tier 3)
// - If still in Redis → re-promoted to blockedCache
// - If expired in Redis too → IP treated as new/clean
```

**Edge Case - Service Restart:**
```
Before restart: IP in blockedCache + Redis
After restart:  IP only in Redis (memory cleared)
First request:  Tier 1 miss → Tier 3 hit → IP re-promoted to Tier 1 cache
```

This design ensures blocked IPs experience minimal latency on rejection while maintaining memory efficiency.

### Memory Safety & Preemptive Bulk LRU Eviction

Protection against memory exhaustion attacks (see [DDOS-DEFENSE.md](DDOS-DEFENSE.md)):

- `MAX_TRACKED_IPS` environment variable (default: 10,000) caps memory usage
- **Preemptive bulk eviction** at 93% capacity (optimized threshold)
- Evicts 10% of oldest IPs in bulk when threshold reached (configurable via `EVICTION_BATCH_PERCENT`)
- Race condition prevention via `evictionInProgress` flag
- Request logs limited to last 100 per IP
- Automatic cleanup of inactive IPs after 1 hour

**Why 93% Threshold?**
After analyzing eviction speed (~50ms for 1000 IPs) and concurrent request patterns:
- **Only 7% memory overhead** - more efficient than previous 10%
- **700 IP buffer** (for 10k limit) - sufficient for typical concurrent bursts (100-300 new IPs)
- **Safe margin** - bulk eviction completes well before hitting hard limit
- **Best balance** - maximizes memory usage without risking limit overflow

**How It Works:**
```go
// Preemptive eviction at 93% capacity with race protection
if currentCount >= d.evictionThreshold && !d.evictionInProgress {
    d.evictionInProgress = true
    go func() {
        d.evictBulkIPsSync()  // Evicts 10% of oldest IPs
        d.evictionInProgress = false
    }()
}
```

**When adding new tracking logic:** Always respect `maxTrackedIPs` limit and use bulk eviction pattern.

### Immediate Blocking for Excessive Nesting (Unforgiving Mode)

**IMPORTANT:** Excessive URL-encoded nesting attacks bypass the deferred analysis system and are blocked on **first detection**. See [IMMEDIATE-BLOCKING.md](../IMMEDIATE-BLOCKING.md) for full details.

**Implementation:**
```go
// In CheckRequest() - BEFORE logging:
if d.hasExcessiveNestingFast(uri) {
    // Block immediately, add to cache, record async
    d.blockedCache[ip] = time.Now().Add(d.blockDuration)
    w.WriteHeader(http.StatusForbidden)
    return
}
```

**Performance:**
- **Fast path (90% of traffic):** ~150ns (early exit if no returnUrl)
- **Malicious request:** ~1,150ns (full pattern check + block)
- **Cached block (subsequent):** ~200ns (Tier 1 cache hit)

**Pattern Detection:**
- Detects 4+ levels of URL-encoded nesting: `returnUrl%25253D`
- Uses optimized string matching (not regex) for speed
- Pre-compiled patterns: `returnUrl%3D`, `returnUrl%253D`, `returnUrl%25253D`

**Why Immediate Blocking:**
1. Prevents backend crashes (HTTP 500 errors)
2. No "free" malicious requests for IP rotation attacks
3. Attack pattern is unambiguous - no false positives
4. Performance impact minimal (~150ns for legitimate traffic)

## Development Environment

### Dev Container (Recommended)

Ops Defender includes a complete VS Code Dev Container configuration for isolated development:

**Location:** `.devcontainer/` directory

**Includes:**
- Go 1.25 with full toolchain (gopls, delve, golangci-lint)
- Azure CLI for cloud deployments
- Docker-in-Docker for container debugging
- Redis service pre-configured
- VS Code extensions (Go, Docker, Azure CLI, YAML)

**Key Features:**
- **Zero host pollution**: All tools run inside container
- **Consistent environment**: Same setup for all developers
- **Full debugging**: Go debugging + Docker container debugging
- **Persistence**: Go modules cache, bash history, Redis data
- **Port forwarding**: 8080 (Ops Defender), 6379 (Redis)

**Usage:**
```bash
# Open in VS Code
code .

# Reopen in container (F1 → "Dev Containers: Reopen in Container")
# Everything auto-configures on first open
```

**Debugging Capabilities:**
1. **Go Application**: Use VS Code debug panel (F5) with pre-configured launch configurations
2. **Docker Containers**: Full docker/docker-compose support inside devcontainer
3. **Remote Attach**: Attach debugger to running containers on port 2345

**When modifying devcontainer:**
- Update `.devcontainer/README.md` with changes
- Test rebuild: F1 → "Dev Containers: Rebuild Container"
- Ensure Docker-in-Docker remains functional for container debugging

**Multi-Root Workspace for Extensions:**

When developing private extensions alongside core system:

```bash
# Clone both repos
git clone https://github.com/luisgizirian/ops-defender.git
git clone https://github.com/your-org/ops-defender-extensions.git

# Create multi-root workspace in VS Code
# File > Add Folder to Workspace (add both folders)
# File > Save Workspace As... → ops-defender.code-workspace

# Reopen in container
# Devcontainer from ops-defender repo will be used
# Extensions can import core types via Go modules
```

See `.devcontainer/README.md` for comprehensive development container guide.

## Project Structure & Responsibilities

```
main.go              - HTTP server, route handlers, environment config, monitoring integration
defender.go          - Core defense logic, pattern analysis, three-tier cache, extension system
storage.go           - Storage abstraction (Redis + in-memory fallback)
reporter.go          - Scheduled reports (daily/weekly), email notifications
metrics.go           - Prometheus/OpenMetrics endpoint, time-series data
events.go            - Server-Sent Events (SSE) for real-time monitoring
telemetry.go         - Azure Application Insights integration
extensions.go        - Extension system interface definitions
test-attacks.sh      - End-to-end attack detection validation
load-test.sh         - Performance testing with mixed traffic
defender_test.go     - Unit tests for pattern detection
.devcontainer/       - VS Code dev container configuration
.vscode/             - VS Code debugging and settings (launch.json, settings.json)
examples/            - Monitoring configurations, dashboards, integration guides
internal/extensions/ - Extension system interfaces and utilities
```

### File-Specific Conventions

**extensions.go** (`pkg/extensions/`):
- Defines `RequestPreHandler` interface for all extensions
- Contains `RequestInfo` and `PreHandlerResult` types
- Helper function `RequestInfoFromHTTP()` for creating RequestInfo from http.Request
- **Do not add business logic here** - keep it pure interface definitions
- **Public package** - can be imported by external modules to implement extensions
- Extensions implementing this interface should be in separate packages/repos

**defender.go:**
- All blocking logic must go through storage interface (Redis/memory)
- Pattern detection uses pre-compiled regex in `suspiciousPatterns`
- New attack patterns: Add to `patterns` slice in `NewDefender()`
- Block events must be recorded via `storage.RecordBlockEvent()` for reporting
- **Extension invocation** happens at start of `CheckRequest()`, before any core logic
- `RegisterExtension()` method for thread-safe extension registration
- Test rebuild: F1 → "Dev Containers: Rebuild Container"
- Ensure Docker-in-Docker remains functional for container debugging

See `.devcontainer/README.md` for comprehensive development container guide.

## Project Structure & Responsibilities

```
main.go              - HTTP server, route handlers, environment config, monitoring integration
defender.go          - Core defense logic, pattern analysis, three-tier cache
storage.go           - Storage abstraction (Redis + in-memory fallback)
reporter.go          - Scheduled reports (daily/weekly), email notifications
metrics.go           - Prometheus/OpenMetrics endpoint, time-series data
events.go            - Server-Sent Events (SSE) for real-time monitoring
telemetry.go         - Azure Application Insights integration
test-attacks.sh      - End-to-end attack detection validation
load-test.sh         - Performance testing with mixed traffic
defender_test.go     - Unit tests for pattern detection
.devcontainer/       - VS Code dev container configuration
.vscode/             - VS Code debugging and settings (launch.json, settings.json)
examples/            - Monitoring configurations, dashboards, integration guides
```

### File-Specific Conventions

**extensions.go** (`pkg/extensions/`):
- Defines extension interfaces: `RequestPreHandler`, `RequestPostHandler`, `PatternAnalyzer`
- Contains extension context/result types: `RequestInfo`, `PreHandlerResult`, `PostHandlerContext`, `PostHandlerResult`, `AnalysisContext`, `AnalysisResult`
- Helper function `RequestInfoFromHTTP()` for creating RequestInfo from http.Request
- **Do not add business logic here** - keep it pure interface definitions
- **Public package** - can be imported by external modules to implement extensions
- Extensions implementing these interfaces should be in separate packages/repos

**defender.go:**
- All blocking logic must go through storage interface (Redis/memory)
- Pattern detection uses pre-compiled regex in `suspiciousPatterns`
- New attack patterns: Add to `patterns` slice in `NewDefender()`
- Block events must be recorded via `storage.RecordBlockEvent()` for reporting
- **Extension invocation** happens at:
  - Start of `CheckRequest()`: PreHandlers (before any core logic)
  - End of `CheckRequest()`: PostHandlers (before HTTP response via `handleFinalResponse()`)
  - During analysis worker: PatternAnalyzers (deferred analysis)
- `RegisterExtension()` method for thread-safe PreHandler registration
- `RegisterPostHandler()` method for thread-safe PostHandler registration
- `RegisterPatternAnalyzer()` method for thread-safe analyzer registration

**storage.go:**
- Two implementations: `RedisStorage` (production) and `MemoryStorage` (dev/testing)
- Redis keys use prefixes: `blocked:{ip}` for blocked IPs, `block_events` sorted set for events
- TTL is critical: Blocked IPs auto-expire after `blockDuration`
- Historical events kept for 7 days, cleaned via `ZRemRangeByScore`
- **CRITICAL:** Always return empty slice `[]BlockedIPInfo{}` on error, never `nil` (prevents nil pointer issues)

**main.go:**
- All HTTP handlers registered here: `/check`, `/health`, `/stats`, `/report`, `/metrics`, `/timeseries`, `/events`
- Environment variables parsed once at startup (no runtime config changes)
- Initializes telemetry (Azure Application Insights) and event stream (SSE) for monitoring
- **Missing /api/users handler** - this is intentional (defender validates auth, doesn't serve content)

**metrics.go:**
- Provides Prometheus/OpenMetrics format endpoint at `/metrics`
- Time-series data endpoint at `/timeseries` for custom dashboards
- All metrics use `ops_defender_` prefix for Prometheus compatibility

**events.go:**
- Server-Sent Events (SSE) implementation for real-time monitoring
- EventStream broadcasts stats updates every 2 seconds
- Broadcasts block events immediately when IPs are blocked
- Clients connect via `/events` endpoint

**telemetry.go:**
- Azure Application Insights integration (optional)
- Batches telemetry events (batch size: 10, flush interval: 30s)
- Tracks IPBlocked events and DefenderStats metrics
- Enabled via `APPINSIGHTS_ENABLED` and `APPINSIGHTS_INSTRUMENTATION_KEY` env vars

## Common Development Workflows

### Adding New Attack Pattern

1. Add regex pattern to `defender.go` `NewDefender()` patterns slice:
   ```go
   patterns := []string{
       // ... existing patterns
       `your-new-pattern`,  // Add here with comment
   }
   ```

2. Test in `test-attacks.sh`:
   ```bash
   test_request \
       "Your Attack Name" \
       "192.168.1.XXX" \
       "/your/malicious/uri" \
       "blocked"
   ```

3. Run validation: `./test-attacks.sh`

### Testing Changes Locally

```bash
# Build
./build.sh

# Run with Redis (production-like)
docker-compose up -d redis
REDIS_URL=redis://localhost:6379/0 ./ops-defender

# Run with memory storage (faster iteration)
./ops-defender

# Validate attack detection
./test-attacks.sh

# Load test
DURATION=60 RPS=20 ./load-test.sh

# Check stats
curl localhost:8080/stats | jq

# Check Prometheus metrics
curl localhost:8080/metrics

# Check time-series data
curl "localhost:8080/timeseries?period=1&interval=5m" | jq

# Test SSE stream (opens in background)
curl localhost:8080/events
```

### Testing Monitoring Features

```bash
# Start the service
./ops-defender

# In another terminal, test monitoring endpoints:

# 1. Prometheus metrics
curl http://localhost:8080/metrics

# 2. Time-series data
curl "http://localhost:8080/timeseries?period=24&interval=1h" | jq

# 3. Server-Sent Events (real-time)
# Use examples/live-dashboard.html or:
curl -N http://localhost:8080/events

# 4. Test with Application Insights
export APPINSIGHTS_ENABLED=true
export APPINSIGHTS_INSTRUMENTATION_KEY=your-key
./ops-defender
```

### Debugging Request Flow

Use `-H "X-Real-IP: ..."` and `-H "X-Original-URI: ..."` headers to simulate Nginx:

```bash
# Send 5 requests to reach analysis threshold
for i in {1..5}; do
  curl -H "X-Real-IP: 10.0.0.1" \
       -H "X-Original-URI: /../etc/passwd" \
       http://localhost:8080/check
done

# Check if blocked
curl -H "X-Real-IP: 10.0.0.1" \
     -H "X-Original-URI: /any/path" \
     http://localhost:8080/check
# Should return 403 (Forbidden)
```

## Environment Variables Reference

| Variable | Default | Purpose | Notes |
|----------|---------|---------|-------|
| `PORT` | `8080` | HTTP server port | |
| `ANALYSIS_THRESHOLD` | `5` | Requests before analysis | Lower = faster blocking, higher false positives |
| `BLOCK_DURATION` | `60` | Block duration (minutes) | 1440 = 24 hours |
| `MAX_TRACKED_IPS` | `10000` | Memory limit protection | ~5MB at 10k IPs, triggers preemptive eviction at 93% (9300 IPs) |
| `EVICTION_BATCH_PERCENT` | `0.10` | Bulk eviction percentage | Evicts 10% of IPs when threshold reached |
| `SIMULATION_MODE` | `false` | Testing mode | When `true`, logs blocks but allows all requests (200) instead of blocking (403) |
| `REDIS_URL` | - | Redis connection | `redis://host:6379/0` format |
| `EMAIL_ENABLED` | `false` | Enable email reports | Requires SMTP config |
| `APPINSIGHTS_ENABLED` | `false` | Enable Azure telemetry | Requires instrumentation key |
| `APPINSIGHTS_INSTRUMENTATION_KEY` | - | Azure App Insights key | Get from Azure Portal |
| `APPINSIGHTS_ENDPOINT` | Azure default | Custom telemetry endpoint | Optional override |

## Proxy Integration (HTTP-Based Architecture)

**IMPORTANT:** Ops Defender does NOT serve application content. It only validates requests via HTTP.

**HTTP API Design:** Ops Defender exposes a `/check` endpoint that accepts any HTTP request and returns:
- **200 OK** = Allow request (proxy continues to backend)
- **403 Forbidden** = Block request (proxy denies access)

**Required Headers:**
- `X-Real-IP` - Client's IP address
- `X-Original-URI` - Original requested URI

This HTTP-based design makes Ops Defender **proxy-agnostic** and compatible with:
- **Nginx** (`auth_request` directive)
- **Caddy** (`forward_auth` handler)
- **Traefik** (`forwardAuth` middleware)
- **HAProxy** (Lua or external check)
- **Apache** (`mod_proxy` + `mod_rewrite`)
- **API Gateways** (AWS, Azure, Kong, etc.)

### Nginx Integration Example

Configuration pattern (see [nginx.conf.example](nginx.conf.example)):

```nginx
# Every request calls Ops Defender first
auth_request /auth;

location = /auth {
    internal;  # Not publicly accessible
    proxy_pass http://localhost:8080/check;
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Real-IP $remote_addr;
}

location / {
    # If /check returns 200: request proceeds
    # If /check returns 403: Nginx blocks with 403
    proxy_pass http://backend;
}
```

**Why test-attacks.sh Test 11 fails:** The test expects `/api/users` to return 200, but Ops Defender doesn't implement application routes - only the `/check` auth endpoint. This is correct behavior. The test should either:
1. Call `/check` endpoint (not `/api/users` directly), OR
2. Mock an actual backend application behind a proxy

## Common Pitfalls

### 1. Adding Blocking I/O to CheckRequest
❌ **Wrong:**
```go
func (d *Defender) CheckRequest(w http.ResponseWriter, r *http.Request) {
    // ... extract IP
    results := d.analyzePattern(ip)  // Blocking analysis!
    if results.suspicious { ... }
}
```

✅ **Correct:**
```go
func (d *Defender) CheckRequest(w http.ResponseWriter, r *http.Request) {
    // ... extract IP
    // Log asynchronously, return immediately
    tracker.RequestLogs = append(tracker.RequestLogs, log)
    w.WriteHeader(http.StatusOK)
    // Analysis happens in background worker
}
```

### 2. Forgetting Redis TTL
When storing blocked IPs in Redis, **always** set TTL matching `blockDuration`:
```go
rs.client.Set(ctx, key, data, duration)  // duration is critical!
```

### 3. Not Respecting Memory Limits
Before adding IP to `ipTrackers`, trigger preemptive bulk eviction:
```go
if currentCount >= d.evictionThreshold && !d.evictionInProgress {
    d.evictionInProgress = true
    go func() {
        d.evictBulkIPsSync()  // Evicts 10% of oldest IPs (93% threshold)
        d.evictionInProgress = false
    }()
}
```

### 4. Testing Without Nginx Headers
Direct calls to `/check` without headers will use `RemoteAddr`, not real client IP:
```bash
# Won't work as expected
curl http://localhost:8080/check

# Correct simulation
curl -H "X-Real-IP: 192.168.1.1" \
     -H "X-Original-URI: /path" \
     http://localhost:8080/check
```

## Performance Expectations

- **Blocked IP (cached):** ~100 nanoseconds (Tier 1 hit)
- **Active IP (tracking):** ~200 nanoseconds (Tier 2 hit)
- **Unknown IP (first request):** ~1-2 milliseconds (Redis call)
- **Analysis threshold:** First 5 requests always < 1ms response time
- **Memory usage:** ~500 bytes per tracked IP, ~40 bytes per blocked IP

## Testing Philosophy

1. **test-attacks.sh:** End-to-end validation of attack detection patterns
2. **load-test.sh:** Performance and memory pressure testing
3. **defender_test.go:** Unit tests for pattern matching logic

Always run both `test-attacks.sh` and `go test` before committing changes.

## Redis vs Memory Storage

**Use Redis when:**
- Production deployment
- Multiple defender instances (shared state)
- Need blocked IPs to persist across restarts
- Distributed architecture

**Use Memory when:**
- Local development/testing
- Single-instance deployment
- Faster iteration (no Redis dependency)
- CI/CD pipelines

## Reporting & Monitoring

Reports generated at:
- **Daily:** 9 AM every day (24h lookback)
- **Weekly:** Monday 9 AM (168h lookback)
- **On-demand:** `curl localhost:8080/report?period=N` (N = hours)

Reports include:
- Block events (IP, timestamp, reason, suspicious URI)
- Top suspicious IPs (most recent blocks)
- Total/blocked request counts
- Memory usage statistics

## Code Style

- Use `context.Context` for all storage operations (Redis timeouts)
- Lock granularity: Hold `mu` for shortest time possible (critical for performance)
- Logging: `log.Printf()` for important events, avoid verbose logging in hot paths
- Error handling: Log errors but don't fail requests (availability > perfect accuracy)

## When to Add New Endpoints

Ops Defender is an **auth validation service**, not an application server. Only add endpoints for:
- Defense-related functionality (`/check`, `/stats`, `/report`)
- Operational health (`/health`)
- Configuration management (future: `/config`)

**Never add:** Application routes, user management, business logic

## Troubleshooting Common Issues

### Test Failures in test-attacks.sh

**Test 11 (Legitimate Request) Always Fails - This is Expected Behavior**

The test sends requests to `/api/users` and expects HTTP 200, but Ops Defender returns 403/404. This is **not a bug**.

**Why:**
- Ops Defender is an **auth validation service**, not an application server
- It only implements endpoints for defense functionality: `/check`, `/health`, `/stats`, `/report`
- It does NOT serve application routes like `/api/users`

**The Test is Incorrect:**
```bash
# Current test (wrong approach):
curl http://localhost:8080/api/users  # Returns 403/404 from Ops Defender

# Correct test should use /check endpoint:
curl -H "X-Real-IP: 192.168.1.200" \
     -H "X-Original-URI: /api/users" \
     http://localhost:8080/check      # Returns 200 (allowed)
```

**Proper Testing Approach:**
1. Test Ops Defender's `/check` endpoint with various URIs via headers
2. In production, Nginx calls `/check` then proxies allowed requests to your backend
3. Your backend application (not Ops Defender) serves `/api/users`

**Integration Flow:**
```
Client → Nginx → Ops Defender /check (auth validation)
                      ↓ 200 (allowed)
         Nginx → Backend Application /api/users → Client
```

**To Fix Test 11:**
Either:
1. Change test to call `/check` endpoint with proper headers, OR
2. Accept that this test demonstrates Ops Defender is NOT an application server (expected behavior)
3. In a real setup, run a mock backend alongside Ops Defender for full integration testing

### Build/Compile Errors

**Missing Dependencies:**
```bash
go mod download
go mod tidy
```

**Redis Connection Issues:**
```bash
# Check Redis is running
docker-compose up -d redis

# Test connection
redis-cli ping

# Use memory storage for development
unset REDIS_URL
./ops-defender
```

### Pattern Detection Not Working

**Symptom:** Malicious requests not getting blocked

**Checklist:**
1. Verify `ANALYSIS_THRESHOLD` is reached (default: 5 requests)
2. Wait 1 second after threshold for analysis to complete
3. Check logs for "IP marked as suspicious and blocked" messages
4. Verify patterns are in `suspiciousPatterns` slice in `NewDefender()`
5. Test pattern matching: `echo "/test/../../etc/passwd" | grep -E '\.\./'`

**Debug Mode:**
```bash
# Check if IP is being tracked
curl http://localhost:8080/stats | jq '.active_ips'

# Check if IP got blocked
curl http://localhost:8080/stats | jq '.blocked_ips'
```

## Common Integration Issues

### HTTP Status Code Mismatch (404 vs 403)

**Problem:** Ops Defender blocks IPs but backend still receives requests and crashes.

**Diagnosis:**
1. Check Ops Defender response: `curl -I -H "X-Real-IP: test" -H "X-Original-URI: /malicious" http://defender:8080/check`
2. Should return **403 Forbidden**, not 404
3. Nginx `error_page 403` won't catch 404 responses

**Fix:** `handleBlockedRequest()` in `defender.go` must return `http.StatusForbidden` (403), not `http.StatusNotFound` (404).

**Why This Matters:**
- Nginx `auth_request` + `error_page 403` only intercepts 403 responses
- 404 responses are treated as routing errors, request proceeds to backend
- Backend receives malicious request → crashes with HTTP 500

### Nginx error_page Placement

**Critical Rule:** `error_page 403` must be at **same scope level** as `auth_request`.

**Wrong:**
```nginx
server {
    include snippets/ops-defender.conf;  # auth_request at server level
    location / {
        error_page 403 = @blocked;  # Location level - TOO LATE!
        proxy_pass http://backend;
    }
}
```

**Correct:**
```nginx
server {
    auth_request /auth;  # Server level
    error_page 403 = @blocked;  # Server level - SAME SCOPE
    location / {
        proxy_pass http://backend;
    }
}
```

**Verification:**
```bash
# Check compiled config scope
nginx -T | grep -B 5 -A 5 "error_page.*403"
# Ensure it appears at same indentation level as auth_request
```

### Debug Logging for Pattern Matching

Add temporary logging to diagnose pattern detection issues:

```go
// In CheckRequest(), after extracting URI:
if strings.Contains(strings.ToLower(uri), "returnurl") {
    log.Printf("DEBUG: IP=%s, URI=%s, HasNesting=%v", ip, uri, d.hasExcessiveNestingFast(uri))
}
```

Expected output:
```
DEBUG: IP=1.2.3.4, URI=/cuenta/crear?returnUrl=.../returnUrl%25253D/..., HasNesting=true
BLOCKED (immediate): IP 1.2.3.4 - excessive nesting on first request
```

If `HasNesting=false` but URI clearly has nesting, check:
1. Nginx is sending `X-Original-URI: $request_uri` (not full URL)
2. Pattern matching in `nestingPatterns` slice covers the encoding level
3. URI isn't being decoded before reaching Ops Defender

## Related Documentation

- [README.md](README.md) - Complete feature documentation
- [DDOS-DEFENSE.md](DDOS-DEFENSE.md) - DDoS protection analysis, memory safety
- [nginx.conf.example](nginx.conf.example) - Integration guide with proper error_page placement
- [IMMEDIATE-BLOCKING.md](IMMEDIATE-BLOCKING.md) - Troubleshooting section for HTTP status and Nginx issues
