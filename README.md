# Ops Defender

> **⚠️ IMPORTANT DISCLAIMER:**  
> This project aims mainly to weed out unwanted down the line processing by leveraging known patterns. It's absolutely not trying to become nor coded consciously to become a security expert and we shouldn't rely on it to act as such.

> **🤖 EXPERIMENTAL PROJECT NOTICE:**  
> This project was created as an **experiment with GitHub Copilot** as the primary development tool. While it demonstrates AI-assisted development capabilities and includes comprehensive testing, **we strongly discourage deploying this directly to production without thorough verification and security review by qualified professionals**.  
>   
> Before considering production use:  
> - ✓ **Conduct comprehensive security audits**  
> - ✓ **Perform extensive testing in staging environments**  
> - ✓ **Review all code and configurations with your security team**  
> - ✓ **Understand the risks and limitations**  
> - ✓ **Have rollback and incident response plans ready**  
>   
> Use this project for learning, experimentation, and as a foundation to build upon—not as a turnkey security solution.

---

## An extensible defensive operations layer for teams running internet-exposed services

Ops-Defender helps engineering and security teams detect, correlate, and respond
to hostile traffic patterns across public web applications and APIs — under their
own control.

- Detect abusive and hostile traffic patterns beyond simple rate limiting
- Correlate signals across services to surface real threats, not noise
- Apply defensive actions and integrations without replacing existing security tools

> High-performance HTTP-based request defense system that detects abuse-like suspicious patterns and blocks malicious IPs using deferred analysis.

## Overview

Analyzes incoming requests asynchronously, tracks suspicious patterns, and automatically blocks malicious IPs without impacting legitimate traffic performance.

Ops Defender runs as a **standalone HTTP service** designed to integrate with **any reverse proxy or API gateway** that can forward HTTP requests. While our examples use Nginx's `auth_request` directive, the HTTP-based architecture makes it compatible with Caddy, Traefik, HAProxy, Apache, or any proxy that can validate requests via HTTP.

## Features

- **IPv4 and IPv6 support** - Full support for both IPv4 and IPv6 addresses
- **Deferred (offline) request pattern analysis** - Non-blocking, doesn't slow down legitimate traffic
- **Automatic IP blocking** after suspicious behavior detected
- **Configurable analysis threshold** (default: 5 requests)
- **Thread-safe IP tracking** with automatic cleanup
- **Memory pressure protection** - Preemptive eviction and health monitoring
- **Persistent error logging** - File-based error tracking for critical issues
- **RESTful API** for Nginx auth_request integration
- **Pattern detection** for common attacks:
  - Path traversal (checked on all requests)
  - SQL injection
  - XSS (Cross-Site Scripting)
  - WordPress exploits
  - Open redirect attacks
  - **Excessive URL-encoded nesting (4+ levels) - IMMEDIATE BLOCKING** ⚡
  - Code injection attempts
  - Sensitive file access (.env, .git, etc.)
- **Immediate blocking** for unforgiving attacks (nesting) - first request blocked
- **Deferred analysis** for other patterns - ~5 requests before blocking
- **Automated reporting** (daily and weekly)
- **Email notifications** (optional)

## How It Works

**HTTP-Based Request Flow:**

1. **Proxy forwards request** to Ops Defender `/check` endpoint (via HTTP)
2. **Immediate check** for unforgiving patterns (excessive nesting):
   - **First malicious request** → blocked immediately (HTTP 403/404)
   - Prevents backend from processing dangerous URLs
3. **Deferred analysis** for other patterns:
   - **First ~5 requests** from any IP are **allowed through** (return 200 OK)
   - Requests are **logged asynchronously** to memory
   - Background worker **analyzes patterns offline**
   - If suspicious patterns detected, IP is **marked as blocked**
4. **Subsequent requests** from blocked IPs return **403 Forbidden**
5. **Proxy blocks request** based on 403 response
6. **Zero performance impact** on request processing - analysis happens in background

This HTTP-based validation approach works with any proxy that can make authorization decisions based on HTTP status codes.

## Quick Start

### Without Extensions (Core System Only)

**Basic standalone usage:**

```bash
# Clone the repository
git clone https://github.com/luisgizirian/ops-defender.git
cd ops-defender

# Build
./scripts/build.sh

# Run with default settings
./ops-defender

# Or with custom configuration
PORT=8080 ANALYSIS_THRESHOLD=5 BLOCK_DURATION=60 ./ops-defender
```

The core system includes all defense features (pattern detection, blocking, reporting) without requiring any extensions.

### Using Dev Container (Recommended for Development)

The easiest way to get started with development is using the VS Code Dev Container, which provides a fully configured development environment with Go, Azure CLI, Docker, and all required tools.

**Prerequisites:**
- [Visual Studio Code](https://code.visualstudio.com/)
- [Docker Desktop](https://www.docker.com/products/docker-desktop)
- [Remote - Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)

**Getting Started:**

```bash
# 1. Clone the repository
git clone https://github.com/luisgizirian/ops-defender.git
cd ops-defender

# 2. Open in VS Code
code .

# 3. When prompted, click "Reopen in Container"
#    Or press F1 and select "Dev Containers: Reopen in Container"

# 4. Wait for the container to build (first time only, ~2-3 minutes)

# 5. The container includes:
#    ✓ Go 1.25 with all tools (gopls, dlv, golangci-lint)
#    ✓ Azure CLI (az)
#    ✓ Docker-in-Docker for testing
#    ✓ Redis service pre-configured
#    ✓ All VS Code extensions installed

# 6. Start developing!
go mod download
./scripts/build.sh
./ops-defender
```

**What You Get:**
- **Isolated Environment**: No pollution of your host system
- **Consistent Setup**: Same environment for all developers
- **Pre-configured Tools**: Go debugging, linting, formatting ready to use
- **Redis Included**: Pre-configured Redis service for testing
- **Azure CLI**: Ready for cloud deployments
- **Docker-in-Docker**: Test docker-compose and containers

**Dev Container Features:**
- Port forwarding: `8080` (Ops Defender), `6379` (Redis)
- Persistent volumes: Go modules cache, bash history
- Pre-installed extensions: Go, Docker, Azure CLI, YAML
- Environment variables: Pre-configured for development

### Using Docker Compose (Recommended for Production)

```bash
# Clone the repository
git clone https://github.com/luisgizirian/ops-defender.git
cd ops-defender

# Start services (includes Redis)
docker-compose up -d

# Check logs
docker-compose logs -f ops-defender

# View stats
curl http://localhost:8080/stats

# Generate report
curl http://localhost:8080/report
```

### Manual Build (Without Docker)

```bash
# Prerequisites: Go 1.25+
go version

# Download dependencies
go mod download

# Build
./scripts/build.sh

# Run without Redis (in-memory mode)
./ops-defender

# Or with Redis for persistence
REDIS_URL=redis://localhost:6379/0 ./ops-defender

# Or with custom configuration
PORT=8080 ANALYSIS_THRESHOLD=5 BLOCK_DURATION=60 ./ops-defender
```

**Build outputs:**
- Binary: `ops-defender` (current directory)
- No extensions required - full functionality included

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Service port | `8080` |
| `ANALYSIS_THRESHOLD` | Number of requests to collect before analysis | `5` |
| `BLOCK_DURATION` | IP block duration in minutes | `60` (1 day = 1440) |
| `MAX_TRACKED_IPS` | Maximum number of IPs to track simultaneously (memory protection) | `10000` |
| `EVICTION_BATCH_PERCENT` | Percentage of IPs to evict in bulk when limit reached (0.01-1.0) | `0.10` (10%) |
| `SIMULATION_MODE` | When `true`, log blocks but allow all requests (testing mode) | `false` |
| `REDIS_URL` | Redis connection URL (optional) | - |
| `APPINSIGHTS_ENABLED` | Enable Azure Application Insights telemetry | `false` |
| `APPINSIGHTS_INSTRUMENTATION_KEY` | Application Insights instrumentation key | - |
| `APPINSIGHTS_ENDPOINT` | Application Insights endpoint (optional) | Azure default |
| `MAX_REPORT_AGE_DAYS` | Days to retain local reports before cleanup | `30` |
| `AZURE_STORAGE_ENABLED` | Enable Azure Blob Storage for report archival | `false` |
| `AZURE_STORAGE_CONNECTION_STRING` | Azure Storage account connection string | - |
| `AZURE_STORAGE_CONTAINER` | Azure Blob container name for reports | `ops-defender-reports` |

### Storage Options

**Redis (Recommended for Production)**

Redis provides persistent storage with automatic expiration:

```bash
# Use Redis for persistent storage
REDIS_URL=redis://localhost:6379/0 ./ops-defender

# Redis with authentication
REDIS_URL=redis://user:password@localhost:6379/0 ./ops-defender

# Redis Cluster/Cloud
REDIS_URL=redis://your-redis-instance:6379/0 ./ops-defender
```

**In-Memory (Development/Testing)**

```bash
# No REDIS_URL set = in-memory storage (data lost on restart)
./ops-defender
```

**Key Benefits of Redis:**
- ✓ Blocked IPs persist across restarts
- ✓ Automatic expiration after block duration (default 24 hours)
- ✓ Historical block events stored for 7 days
- ✓ Shared state across multiple defender instances
- ✓ In-memory cache still used for performance (no Redis hit on cached IPs)

**Storage Flow:**
```
IP Blocked → Add to blockedCache (memory) → Store in Redis (TTL=24h)
                ↓
    Next request hits cache (no Redis call)
                ↓
    After 24h: Redis expires, cache cleaned up
```

### Fail-Open Error Handling

**Resilience During Infrastructure Issues**

Ops Defender prioritizes **availability over perfect security** when Redis/storage becomes unavailable. If Redis connectivity fails, the service **fails open** (allows requests) rather than blocking all traffic with HTTP 500 errors.

**Behavior on Redis Errors:**
- ✓ `/check` endpoint: Always returns `200 OK` (allow request through)
- ✓ `/metrics`, `/timeseries`, `/stats`: Return partial data with empty blocked IP lists (never `nil`)
- ✓ `/report`: Returns report with empty block events
- ✓ In-memory caching continues to work (previously blocked IPs still blocked from cache)
- ✓ Service logs warnings about Redis errors but continues operating
- ✓ Storage methods return empty slices `[]BlockedIPInfo{}` instead of `nil` to prevent runtime errors

**Why Fail-Open:**
1. **Availability Priority:** Better to allow some malicious traffic temporarily than block all legitimate users
2. **Redis is Optional:** System designed to work (degraded) without Redis using in-memory caching
3. **Testing Flexibility:** Run and test without Redis infrastructure
4. **Operational Resilience:** Service continues during Redis maintenance/failures

**Example Error Handling:**
```go
// Redis error in /check endpoint
blocked, err := storage.IsBlocked(ctx, ip)
if err != nil {
    log.Printf("WARNING: Redis error, allowing request: %v", err)
    blocked = false  // Fail-open: allow request through
}
```

**When This Matters:**
- **Production:** During Redis outages, legitimate traffic continues uninterrupted
- **Testing:** Can run without Redis dependency for local development
- **Staging:** Test configurations without full infrastructure

**Security Consideration:**  
If your threat model requires **hard blocking** (fail-closed) behavior where all traffic should be blocked during infrastructure failures, you'll need to modify the error handling in the following handlers:
- `CheckRequest()` in [internal/defender/defender.go](internal/defender/defender.go)
- `MetricsHandler()` in [internal/defender/metrics.go](internal/defender/metrics.go)  
- `TimeSeriesHandler()` in [internal/defender/metrics.go](internal/defender/metrics.go)

For high-security environments, combine fail-closed logic with Redis High Availability (HA) setup.

### Simulation Mode

**Testing Without Impact**

Simulation mode allows you to test Ops Defender's blocking behavior without actually blocking requests. This is useful for:
- Testing new patterns before deploying to production
- Validating configuration changes
- Understanding what would be blocked in your traffic
- Dry-run before enabling production blocking

```bash
# Enable simulation mode
SIMULATION_MODE=true ./ops-defender

# Or with Docker
docker run -e SIMULATION_MODE=true ops-defender
```

**Behavior in Simulation Mode:**
- ✓ All requests return `200 OK` (never blocked)
- ✓ Attack patterns are still detected and analyzed
- ✓ IPs are tracked and "blocked" internally (visible in stats)
- ✓ Block events are logged with `[SIMULATION]` prefix
- ✓ Monitoring and reporting work normally
- ✓ Historical data is collected

**Example Log Output:**
```
2025/12/21 19:25:01 [SIMULATION] IP would be blocked: 10.0.0.96 (reason: Suspicious URL pattern detected, pattern: /wp-admin/admin.php, expires: 2025-12-21T20:25:01Z) - but allowing all requests in simulation mode
2025/12/21 19:25:04 [SIMULATION] Would block IP 10.0.0.96 (blocked in cache), but allowing request: /any-path
```

**Use Cases:**
1. **Pre-Production Testing:** Validate that legitimate traffic won't be blocked
2. **Pattern Tuning:** Test new suspicious patterns without affecting users
3. **Traffic Analysis:** Understand attack patterns in your environment
4. **Gradual Rollout:** Deploy with simulation mode first, then disable once validated

### Email Reporting (Optional)

| Variable | Description | Example |
|----------|-------------|---------|
| `EMAIL_ENABLED` | Enable email reports | `true` |
| `EMAIL_TO` | Recipient email | `ops@example.com` |
| `EMAIL_FROM` | Sender email | `defender@example.com` |
| `SMTP_HOST` | SMTP server | `smtp.gmail.com` |
| `SMTP_PORT` | SMTP port | `587` |
| `SMTP_USER` | SMTP username | `your-email@gmail.com` |
| `SMTP_PASSWORD` | SMTP password/app token | `your-app-password` |

## Proxy Integration

### HTTP-Based Architecture

Ops Defender uses a standard HTTP API (`/check` endpoint) for request validation, making it **proxy-agnostic**. Any reverse proxy or API gateway that can:
1. Forward requests to an HTTP endpoint
2. Make routing decisions based on HTTP status codes
3. Pass original client IP and URI as headers

...can integrate with Ops Defender.

### Nginx Integration

**Critical Requirements:**
- Ops Defender returns **HTTP 403 Forbidden** for blocked IPs
- `error_page 403` directive **must** be at same scope level as `auth_request` to intercept blocks

Add to your Nginx server block:

```nginx
server {
    listen 80;
    server_name example.com;

    # Ops Defender auth check
    auth_request /auth;
    
    # CRITICAL: Intercept 403 responses at same level as auth_request
    # Without this, blocked requests reach backend and may cause HTTP 500
    error_page 403 = @defender_blocked;
    
    location = /auth {
        internal;
        proxy_pass http://localhost:8080/check;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;  # Path only, not full URL
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    
    # Handle blocked requests
    location @defender_blocked {
        return 403 "Access Denied - Suspicious Activity Detected\n";
    }

    # Your application
    location / {
        # Only reached if /auth returns 200 (IP allowed)
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

**Common Issue:** If `error_page 403` is placed inside `location /` instead of server level, Nginx won't intercept the 403 response and malicious requests will reach your backend.

See [nginx.conf.example](nginx.conf.example) for complete configuration and [IMMEDIATE-BLOCKING.md](IMMEDIATE-BLOCKING.md) troubleshooting guide.

### Other Proxy Solutions

**Caddy Integration:**
```caddy
example.com {
    @blocked {
        header X-Real-IP {remote_host}
        header X-Original-URI {uri}
        forward_auth localhost:8080 {
            uri /check
            copy_headers X-Real-IP X-Original-URI
        }
    }
    handle @blocked {
        respond 403
    }
    reverse_proxy localhost:3000
}
```

**Traefik Integration (via ForwardAuth middleware):**
```yaml
http:
  middlewares:
    ops-defender:
      forwardAuth:
        address: "http://localhost:8080/check"
        authResponseHeaders:
          - "X-Real-IP"
          - "X-Original-URI"
  routers:
    my-router:
      rule: "Host(`example.com`)"
      middlewares:
        - ops-defender
      service: my-service
```

**HAProxy Integration:**
```haproxy
frontend http-in
    bind *:80
    http-request lua.ops_check
    http-request deny if { var(txn.ops_blocked) -m int 1 }
    default_backend app-servers

# Lua script to call Ops Defender /check endpoint
```

**Apache Integration (mod_proxy + mod_rewrite):**
```apache
<Location />
    RewriteEngine On
    RewriteCond %{ENV:Ops_CHECK} !=passed
    RewriteRule .* http://localhost:8080/check [P,E=Ops_CHECK:passed]
    # Handle 403 response from Ops Defender
</Location>
```

> **Note:** The above examples demonstrate the HTTP-based integration approach. Exact configuration varies by proxy. The key is forwarding the request to `/check` with `X-Real-IP` and `X-Original-URI` headers, then blocking on 403 Forbidden response.

## API Endpoints

### Authentication & Request Validation

#### `GET /check`
- **Purpose**: Validate incoming requests (called by Nginx auth_request)
- **Returns**: 200 (allow) or 403 (block)
- **Headers Required**: `X-Real-IP`, `X-Original-URI`

#### `GET /health`
- **Purpose**: Health check endpoint
- **Returns**: `OK`

### Statistics & Reporting

#### `GET /stats`
- **Purpose**: Get current statistics snapshot
- **Response**:
```json
{
  "total_ips": 150,
  "blocked_ips": 12,
  "active_ips": 138,
  "total_requests": 45000,
  "blocked_requests": 234,
  "memory_usage": {
    "tracked_ips": 138,
    "max_tracked_ips": 10000,
    "dropped_ips": 0,
    "usage_percent": 1.38
  },
  "top_ips": [...]
}
```

#### `GET /report?period=24`
- **Purpose**: Generate detailed activity report
- **Parameters**: `period` (hours, default: 24)
- **Response**:
```json
{
  "generated_at": "2025-12-18T02:13:00Z",
  "period": "Last 24 hours",
  "total_requests": 45000,
  "blocked_requests": 234,
  "block_events": [...],
  "top_suspicious_ips": [...]
}
```

### Monitoring & Visualization

#### `GET /metrics`
- **Purpose**: Prometheus/OpenMetrics format metrics
- **Format**: Text (Prometheus exposition format)
- **Use with**: Prometheus, Grafana, Datadog, New Relic
- **Metrics**:
  - `ops_defender_total_requests` - Counter of total requests
  - `ops_defender_blocked_requests` - Counter of blocked requests
  - `ops_defender_active_ips` - Gauge of active IPs
  - `ops_defender_blocked_ips` - Gauge of blocked IPs
  - `ops_defender_memory_usage_percent` - Memory utilization
  - `ops_defender_block_rate_percent` - Block rate percentage

#### `GET /timeseries?period=24&interval=1h`
- **Purpose**: Time-series data for custom dashboards
- **Parameters**:
  - `period` - Hours of historical data (default: 24)
  - `interval` - Bucket size: `5m`, `15m`, `30m`, `1h`, `6h`, `1d`
- **Response**:
```json
{
  "start_time": "2025-12-20T16:00:00Z",
  "end_time": "2025-12-21T16:00:00Z",
  "interval": "1h",
  "time_series": [
    {
      "metric": "block_events",
      "data_points": [
        {"timestamp": "2025-12-20T16:00:00Z", "value": 5}
      ]
    }
  ]
}
```

#### `GET /events`
- **Purpose**: Real-time Server-Sent Events (SSE) stream
- **Format**: text/event-stream
- **Use with**: Live dashboards, NOC displays
- **Events**:
  - `connected` - Initial connection confirmation
  - `stats_update` - Stats update every 2 seconds
  - `ip_blocked` - Real-time block notifications

**Example SSE Client:**
```javascript
const eventSource = new EventSource('http://localhost:8080/events');
eventSource.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(data.type, data.data);
};
```

## Monitoring & Visualization

Ops Defender provides comprehensive monitoring integration:

### Quick Start Monitoring

1. **Prometheus + Grafana** (Recommended):
   ```bash
   # See examples/prometheus.yml and examples/grafana-dashboard.json
   # Import dashboard for instant visualization
   ```

2. **Azure Application Insights**:
   ```bash
   export APPINSIGHTS_ENABLED=true
   export APPINSIGHTS_INSTRUMENTATION_KEY=your-key
   # See examples/AZURE-INSIGHTS.md for KQL queries and alerts
   ```

3. **Real-time Dashboard** (SSE):
   ```html
   <!-- Simple live dashboard -->
   <script>
     const es = new EventSource('/events');
     es.onmessage = e => console.log(JSON.parse(e.data));
   </script>
   ```

### Available Integrations

| Tool | Endpoint | Format | Features |
|------|----------|--------|----------|
| Prometheus/Grafana | `/metrics` | OpenMetrics | Alerting, long-term storage, visualization |
| Azure App Insights | Telemetry API | Custom events | AI analytics, correlation, Azure integration |
| Custom Dashboards | `/timeseries` | JSON | Time-series data, flexible intervals |
| Live NOC Display | `/events` | SSE | Real-time updates, zero polling |
| Scripts/CLI | `/stats` | JSON | Quick snapshots, automation |

**See [examples/MONITORING.md](examples/MONITORING.md) for comprehensive guide including:**
- Grafana dashboard templates
- Prometheus alert rules
- Azure Application Insights queries
- Real-time SSE dashboard examples
- Best practices and troubleshooting

## Reporting

Ops Defender automatically generates:
- **Daily Reports**: 9 AM every day
- **Weekly Reports**: Monday 9 AM
- **Cleanup**: 3 AM every day (removes reports older than retention period)

Reports are:
- Saved to `reports/` directory as JSON
- Automatically cleaned up after retention period (default: 30 days)
- Optionally uploaded to Azure Blob Storage for long-term archival
- Logged to console with formatted summary
- Optionally emailed to ops team

### Report Storage Management

**Local Report Retention:**
```bash
# Default: keep reports for 30 days
MAX_REPORT_AGE_DAYS=30 ./ops-defender

# Keep reports for 7 days (saves disk space)
MAX_REPORT_AGE_DAYS=7 ./ops-defender

# Keep reports for 90 days
MAX_REPORT_AGE_DAYS=90 ./ops-defender

# Disable cleanup (keep all reports)
MAX_REPORT_AGE_DAYS=0 ./ops-defender
```

**Azure Blob Storage Archival (Optional):**

For production deployments, you can optionally archive reports to Azure Blob Storage for long-term retention while keeping local storage clean:

```bash
# Enable Azure Blob Storage upload
export AZURE_STORAGE_ENABLED=true
export AZURE_STORAGE_CONNECTION_STRING="DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=..."
export AZURE_STORAGE_CONTAINER="ops-defender-reports"  # Optional, default shown

# Reports are uploaded to Azure AND saved locally
./ops-defender
```

**How It Works:**
1. **Local Reports**: Saved to `reports/` directory
2. **Azure Upload**: If enabled, reports are uploaded to Azure Blob Storage immediately with automatic retry (3 attempts with exponential backoff)
3. **Cleanup**: Daily at 3 AM, local reports older than `MAX_REPORT_AGE_DAYS` are deleted
4. **Azure Archive**: Reports in Azure remain indefinitely (use Azure lifecycle policies for cloud-side retention)

**Upload Failure Handling:**
- **Automatic Retry**: 3 upload attempts with exponential backoff (2s, 4s, 8s)
- **Local Fallback**: If Azure upload fails after retries, report remains saved locally
- **Error Logging**: Detailed error messages logged for troubleshooting
- **No Data Loss**: Report generation continues even if Azure is unavailable

**Benefits:**
- **Disk Space Management**: Local reports automatically cleaned up
- **Long-term Archival**: Azure Blob Storage keeps historical data
- **Cost Optimization**: Cheap cloud storage for compliance/audit needs
- **Resilient Upload**: Automatic retry handles transient network issues
- **No Data Loss**: Reports uploaded before local cleanup, local fallback on Azure failure

**Azure Blob Storage Setup:**
```bash
# 1. Create storage account (Azure Portal or CLI)
az storage account create --name opsdefender --resource-group mygroup --location eastus

# 2. Get connection string
az storage account show-connection-string --name opsdefender --resource-group mygroup

# 3. Create container (auto-created if missing, or create manually)
az storage container create --name ops-defender-reports --connection-string "..."

# 4. Configure Ops Defender
export AZURE_STORAGE_ENABLED=true
export AZURE_STORAGE_CONNECTION_STRING="<connection-string-from-step-2>"
```

**Azure Lifecycle Policies (Optional):**
Set up Azure lifecycle management to automatically tier or delete old reports:
```bash
# Example: Move reports >90 days to Cool tier, delete after 365 days
# Configure via Azure Portal > Storage Account > Lifecycle Management
```

### Manual Report Generation

```bash
# Daily report (24 hours)
curl http://localhost:8080/report

# Weekly report (7 days)
curl http://localhost:8080/report?period=168

# Custom period (48 hours)
curl http://localhost:8080/report?period=48
```

## Development & Testing

### Local Development

```bash
# Install dependencies
go mod download

# Run tests
go test -v ./...

# Run with verbose logging
LOG_LEVEL=debug ./ops-defender

# Build for production
CGO_ENABLED=0 go build -ldflags="-s -w" -o ops-defender
```

### Automated Attack Detection Testing

Use the provided test script to validate all attack detection patterns:

```bash
# Run the full test suite
./test-attacks.sh

# Run with verbose output
VERBOSE=true ./test-attacks.sh

# Test against a different endpoint
DEFENDER_URL=http://your-server.com:8080 ./test-attacks.sh
```

The test script validates:
- ✓ Path traversal detection
- ✓ SQL injection detection
- ✓ XSS attack detection
- ✓ WordPress exploit detection
- ✓ Open redirect detection
- ✓ Excessive URL-encoded nesting detection
- ✓ Sensitive file access blocking
- ✓ Rate limit enforcement
- ✓ Legitimate traffic handling

> **Note on Test 11:** This test currently fails because it attempts to access `/api/users` directly on Ops Defender, which only implements auth validation endpoints (`/check`, `/health`, `/stats`, `/report`). In production, Nginx calls Ops Defender's `/check` endpoint for validation, then proxies allowed requests to your backend application. To properly test legitimate requests, use:
> ```bash
> curl -H "X-Real-IP: 192.168.1.200" \
>      -H "X-Original-URI: /api/users" \
>      http://localhost:8080/check  # Returns 200 (allowed)
> ```

### Load Testing

Simulate realistic traffic with the load test script:

```bash
# Run 60-second load test at 10 req/s
./load-test.sh

# Custom duration and rate
DURATION=300 RPS=50 ./load-test.sh

# Adjust attack ratio (default 10%)
ATTACK_RATIO=0.2 ./load-test.sh  # 20% attacks
```

The load test:
- Generates mixed legitimate and attack traffic
- Uses realistic IP distributions
- Reports block rates and statistics
- Validates defender performance under load

### Testing Attack Detection

```bash
# Start the service
./ops-defender

# In another terminal, test suspicious patterns:

# 1. Path traversal attempt (IPv4)
curl -H "X-Real-IP: 192.168.1.100" \
     -H "X-Original-URI: /../../../etc/passwd" \
     http://localhost:8080/check

# 2. SQL injection attempt (IPv4)
curl -H "X-Real-IP: 192.168.1.101" \
     -H "X-Original-URI: /users?id=1 UNION SELECT * FROM users" \
     http://localhost:8080/check

# 3. Open redirect attempt (IPv4)
curl -H "X-Real-IP: 192.168.1.102" \
     -H "X-Original-URI: /login?redirect=http://evil.com" \
     http://localhost:8080/check

# 4. Excessive URL-encoded nesting
curl -H "X-Real-IP: 192.168.1.103" \
     -H "X-Original-URI: /cuenta/crear?returnUrl=/cuenta/crear?returnUrl%3D/cuenta/ingresar?returnUrl%253D/cuenta/crear?returnUrl%25253D/productos" \
     http://localhost:8080/check

# 5. Rate limiting (send 10 rapid requests)
for i in {1..10}; do
  curl -H "X-Real-IP: 192.168.1.104" \
       -H "X-Original-URI: /api/data" \
       http://localhost:8080/check
done

# 5. IPv6 path traversal attempt
curl -H "X-Real-IP: 2001:db8::1" \
     -H "X-Original-URI: /../../../etc/passwd" \
     http://localhost:8080/check

# 6. IPv6 WordPress exploit
for i in {1..5}; do
  curl -H "X-Real-IP: 2001:db8::2" \
       -H "X-Original-URI: /wp-admin" \
       http://localhost:8080/check
done

# Check which IPs got blocked
curl http://localhost:8080/stats | jq '.top_ips[] | select(.blocked == true)'
```

### IPv6 Testing

Run the dedicated IPv6 test suite:

```bash
# Build the service first
./build.sh

# Run comprehensive IPv6 tests
./scripts/test-ipv6.sh
```

The test validates:
- IPv6 address extraction from headers (X-Real-IP, X-Forwarded-For)
- IPv6 address extraction from RemoteAddr
- IPv6 blocking and storage
- Mixed IPv4/IPv6 traffic handling
- Various IPv6 formats (compressed, full, loopback, link-local)

### Live Testing with a Proxy

```bash
# 1. Start Ops Defender
docker-compose up -d ops-defender

# 2. Configure your proxy (examples: nginx.conf.example or Proxy Integration section above)
# For Nginx:
sudo cp nginx.conf.example /etc/nginx/sites-available/defended-app
sudo ln -s /etc/nginx/sites-available/defended-app /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# For other proxies, see Proxy Integration section

# 3. Monitor logs
docker-compose logs -f ops-defender

# 4. Test from external client
curl -v http://your-server.com/../../../etc/passwd
# Should return 403 (Forbidden) after analysis threshold

# 5. Check reports
curl http://localhost:8080/stats
```

### Docker Testing

```bash
# Build image
docker build -t ops-defender .

# Run standalone
docker run -p 8080:8080 \
  -e ANALYSIS_THRESHOLD=3 \
  -e BLOCK_DURATION=30 \
  ops-defender

# Run with docker-compose
docker-compose up

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Project Structure

```
.
├── cmd/
│   └── ops-defender/
│       └── main.go          # Application entry point
├── internal/
│   ├── config/              # Configuration management
│   ├── defender/            # Core defense logic, metrics, and telemetry
│   ├── reporter/            # Report generation and scheduling
│   └── storage/             # Redis and in-memory storage backends
├── scripts/
│   ├── build.sh             # Build script
│   ├── load-test.sh         # Load testing script
│   └── test-attacks.sh      # Attack detection test suite
├── go.mod                   # Go module definition
├── Dockerfile               # Multi-stage Docker build
├── docker-compose.yml       # Full stack with Redis
├── nginx.conf.example       # Nginx configuration template
└── README.md                # This file
```

## How Data Flows

### New Request from Unknown IP
```
1. Proxy (Nginx/Caddy/Traefik/etc.) → Ops Defender /check endpoint
2. Tier 1: Cache miss (not blocked)
3. Tier 2: Not in ipTrackers (new IP)
4. Tier 3: Check Redis → not found
5. Create tracker, log request
6. Return 200 OK → Proxy allows request through
```

### Request from Active IP (Being Analyzed)
```
1. Proxy → Ops Defender /check endpoint
2. Tier 1: Cache miss (not blocked)
3. Tier 2: Found in ipTrackers
4. Skip Redis (already tracking)
5. Log request, check if threshold reached
6. If threshold reached → queue for analysis
7. Return 200 OK → Proxy allows request through
```

### Request from Blocked IP
```
1. Proxy → Ops Defender /check endpoint
2. Tier 1: Cache HIT (blocked, expires at X)
3. Return 403 Forbidden immediately
4. Proxy blocks request (403 to client)
5. No Redis call, no further processing
```

### When IP Gets Blocked (Analysis Complete)
```
1. Background worker detects suspicious pattern
2. Add to blockedCache (Tier 1) with expiry time
3. Store in Redis (Tier 3) with TTL
4. Record block event for reporting
5. Future requests instantly blocked (Tier 1) → Proxy returns 403
```
```

### Blocked IP Lifecycle & Cache Persistence

**Once an IP is blocked, it stays in Tier 1 cache until expiration:**

```
Blocked IP Added:
- blockedCache[ip] = time.Now().Add(blockDuration)  // e.g., +60 minutes
- Also stored in Redis with same TTL

Subsequent Requests (e.g., attacker retrying):
- Check blockedCache → HIT → return 403 (~100 nanoseconds)
- IP STAYS in cache - no demotion to Redis
- No additional Redis calls needed

After Block Duration Expires:
- Time-based check finds time.Now().After(expiresAt)
- IP removed from blockedCache
- Next request → Redis check → if expired there too, IP treated as clean

Service Restart:
- blockedCache cleared (in-memory)
- Blocked IPs still in Redis (persistent)
- First request → Tier 3 hit → IP re-promoted to Tier 1 cache
```

**Key Design Benefits:**
- **No demotion**: Blocked IPs never get evicted from cache during block period (unlike active IP tracking)
- **Minimal memory**: ~40 bytes per blocked IP
- **Maximum performance**: Repeated block checks are pure memory lookups
- **Guaranteed duration**: Block time is deterministic - no early eviction

## Security Considerations

> **⚠️ IMPORTANT DISCLAIMER:**  
> This project aims mainly to weed out unwanted down the line processing by leveraging known patterns. It's absolutely not trying to become nor coded consciously to become a security expert and we shouldn't rely on it to act as such.

- Ops Defender is designed as a **defense-in-depth layer**, not a replacement for proper application security
- Always keep your application code secure and patched
- Monitor reports regularly for attack trends
- Adjust `ANALYSIS_THRESHOLD` based on your traffic patterns
- Use HTTPS for production deployments
- Restrict access to `/stats` and `/report` endpoints in production

### Memory Safety and DoS Protection

Ops Defender includes built-in protection against memory exhaustion attacks:

**Memory Limits:**
- Configurable maximum tracked IPs via `MAX_TRACKED_IPS` (default: 10,000)
- **Bulk LRU eviction** when limit is reached (evicts 10% of IPs at once)
- Request logs limited to last 100 per IP
- Automatic cleanup of inactive IPs after 1 hour

**How It Works:**
The system uses **preemptive bulk eviction** to maintain optimal performance:
- Eviction triggers at **93% capacity** (optimized for memory efficiency and safety)
- Evicts **10% of oldest IPs in bulk** when threshold reached
- **Race condition prevention**: Only one eviction runs at a time, even under concurrent load
- Much more efficient than evicting one IP at a time

**Why 93% Threshold?**
After analysis of eviction speed and concurrent request patterns, 93% provides the optimal balance:
- **Only 7% memory overhead** - more efficient than previous 10%
- **700 IP buffer** (for 10k limit) - sufficient for typical concurrent bursts (100-300 new IPs)
- **Safe margin** - bulk eviction completes (~50ms) well before hitting hard limit
- **Best of both worlds** - maximizes memory usage without risking limit overflow

**Preemptive Eviction Benefits:**
- **Proactive**: Triggers before hitting hard limit (93% vs 100%)
- **Efficient**: Evicts multiple IPs at once (default: 10% of max) instead of one at a time
- **Race-safe**: Concurrent requests won't trigger duplicate evictions
- **Non-blocking**: Eviction happens asynchronously
- **Optimized**: 93% threshold balances memory efficiency with safety

**Example:**
```bash
# With MAX_TRACKED_IPS=10000
# Triggers at 9300 IPs (93%), evicts 1000 IPs, drops to ~8300
# Only wastes 700 IPs (7%) instead of 1000 (10%)
MAX_TRACKED_IPS=10000 ./ops-defender
```

**Monitoring Memory Usage:**
```bash
curl http://localhost:8080/stats | jq '.memory_usage'
```

**Response:**
```json
{
  "tracked_ips": 8543,
  "max_tracked_ips": 10000,
  "dropped_ips": 127,
  "dropped_analysis": 0,
  "analysis_worker_restarts": 0,
  "usage_percent": 85.43
}
```

**New Health Metrics (Added for Operational Reliability):**
- `dropped_analysis`: Count of analysis requests dropped when worker channel is full
  - **Normal**: 0 (worker keeping up with load)
  - **Warning**: > 0 (worker may be slow or under heavy load)
  - **Critical**: Large values indicate worker issues
- `analysis_worker_restarts`: Count of times analysis worker recovered from panic
  - **Normal**: 0 (no panics occurred)
  - **Warning**: Any value > 0 indicates recurring issues requiring investigation
  - **Action**: Check error logs for panic stack traces

**Automatic Health Monitoring:**

Ops Defender includes built-in health monitoring that logs status every 10 minutes:

```
HEALTH: Analysis worker restarts=0, dropped_analysis=0, channel_usage=2.3% (23/1000), tracked_ips=145/10000
```

**Warning Conditions:**
- `analysis_worker_restarts > 0`: Worker has crashed and restarted (check logs)
- `dropped_analysis > 0`: Analysis requests being dropped (worker overwhelmed)
- `channel_usage > 80%`: Analysis channel nearing capacity (worker falling behind)

**Automatic Recovery:**
- Analysis worker automatically restarts on panic with 1-second delay
- Panic details logged to console and error log file (if configured)
- System continues operating during worker restart (fail-open behavior)
- Health metrics track recovery events for monitoring

**Production Tuning:**
- **Small deployments** (< 1000 concurrent users): `MAX_TRACKED_IPS=5000`
- **Medium deployments** (1000-10000 users): `MAX_TRACKED_IPS=10000` (default)
- **Large deployments** (10000+ users): `MAX_TRACKED_IPS=50000` with sufficient RAM

**Memory Estimation:**
- ~500 bytes per tracked IP
- 10,000 IPs ≈ 5 MB memory
- 50,000 IPs ≈ 25 MB memory

**Can Memory Logging Be Exploited?**

Yes, without proper limits, an attacker could attempt a memory exhaustion attack by sending requests from many unique IPs. However, Ops Defender mitigates this through:

1. **Hard memory limits**: `MAX_TRACKED_IPS` prevents unbounded growth
2. **Bulk LRU eviction**: 10% of oldest IPs evicted at once when limit reached
3. **Automatic cleanup**: Inactive IPs removed after 1 hour
4. **Request log limits**: Only last 100 requests kept per IP
5. **Monitoring**: Memory usage visible in `/stats` endpoint
6. **Panic recovery**: Analysis worker automatically restarts on crashes
7. **Health monitoring**: Periodic logging of system health metrics

**Best Practice:** Use Redis storage for production deployments to enable persistent blocking across restarts and distributed deployments, reducing memory pressure on individual instances.

See [DDOS-DEFENSE.md](DDOS-DEFENSE.md) for detailed analysis of DDoS protection capabilities and memory attack scenarios.

## Performance

### Request Latency

| Scenario | Cache Status | Latency | Redis Calls |
|----------|--------------|---------|-------------|
| Blocked IP (cached) | Tier 1 hit | ~100 nanoseconds | 0 |
| Active IP (tracking) | Tier 2 hit | ~200 nanoseconds | 0 |
| Unknown IP (first time) | Tier 3 | ~1-2 milliseconds | 1 |
| Subsequent blocked requests | Tier 1 hit | ~100 nanoseconds | 0 |

### Characteristics

- **Async analysis**: Zero impact on request latency
- **Memory efficient**: ~40 bytes per blocked IP, ~500 bytes per active IP
- **Concurrent safe**: Mutex-protected shared state
- **Lightweight**: ~10MB Docker image (Alpine-based)
- **Fast pattern matching**: Pre-compiled regex patterns
- **Intelligent caching**: 99% of requests served from memory

### Example Load Profile

```
1000 blocked IPs + 5000 active IPs:
- Blocked cache: ~40 KB
- Active tracking: ~2.5 MB
- Total memory: ~2.5 MB
- Redis calls/sec: <1% of total requests
```

## Troubleshooting

### Test 11 (test-attacks.sh) Fails - Expected Behavior

**Symptom:** Test 11 "Legitimate Request" returns 403/404 when accessing `/api/users`

**Explanation:** This is **not a bug**. Ops Defender is an auth validation service, not an application server. It only implements:
- `/check` - Auth validation endpoint (for Nginx)
- `/health` - Health check
- `/stats` - Statistics
- `/report` - Reporting

**Why the test is misleading:**
```bash
# Current test (incorrect):
curl http://localhost:8080/api/users  # Returns 403/404 (not a valid endpoint)

# Correct approach:
curl -H "X-Real-IP: 192.168.1.200" \
     -H "X-Original-URI: /api/users" \
     http://localhost:8080/check      # Returns 200
```

**In production:** Nginx calls `/check` for validation, then proxies allowed requests to your backend application that serves `/api/users`.

### Defender not blocking suspicious requests
- Check that `ANALYSIS_THRESHOLD` has been reached (default: 5 requests)
- Verify Nginx is passing correct headers (`X-Real-IP`, `X-Original-URI`)
- Review logs: `docker-compose logs ops-defender`
- **New**: Check health metrics: `curl http://localhost:8080/stats | jq '.memory_usage'`
  - If `analysis_worker_restarts > 0`: Worker crashed and restarted (check error logs)
  - If `dropped_analysis > 0`: Analysis queue is full (worker overwhelmed)

### Website not rendering / All requests allowed after some time

**Symptom:** After running for 0.5-2 days, all malicious requests are allowed through and no new IPs get blocked, even though Ops Defender appears to be running.

**Root Cause:** Analysis worker goroutine died silently without recovery mechanism (fixed in v1.x).

**Diagnosis:**
```bash
# Check health metrics
curl http://localhost:8080/stats | jq '.memory_usage'

# Look for these indicators:
# - analysis_worker_restarts: > 0 (worker crashed)
# - dropped_analysis: high number (queue filling up)
```

**Solution (v1.x and later):**
- **Automatic recovery:** Analysis worker now restarts automatically on panic
- **Health monitoring:** System logs health status every 10 minutes
- **Metrics tracking:** `analysis_worker_restarts` and `dropped_analysis` counters added

**If using older version (pre-v1.x):**
- Upgrade to latest version with panic recovery
- Monitor error logs: `/var/log/ops-defender/errors.log`
- Set up alerting on `analysis_worker_restarts` metric

**Prevention:**
```bash
# Enable persistent error logging
ERROR_LOG_PATH=/var/log/ops-defender/errors.log ./ops-defender

# Monitor health metrics
watch -n 60 'curl -s http://localhost:8080/stats | jq ".memory_usage"'

# Set up alerts (Prometheus example)
alert: AnalysisWorkerRestarted
expr: ops_defender_analysis_worker_restarts > 0
for: 1m
annotations:
  summary: "Analysis worker has crashed and restarted"
```

### Legitimate traffic being blocked
- Review block events: `curl http://localhost:8080/report`
- Adjust patterns in `defender.go` if needed
- Increase `ANALYSIS_THRESHOLD` for more tolerance

### Reports not being generated
- Check file permissions on `reports/` directory
- Verify scheduler is running: check logs for "Next daily report scheduled"
- For email: validate SMTP credentials

### Memory pressure or crashes after high traffic
- Check error log: `/var/log/ops-defender/errors.log` or `/tmp/ops-defender/errors.log`
- Monitor Redis sorted set size: `redis-cli ZCARD block_events`
- See **[MEMORY-PRESSURE-FIX.md](MEMORY-PRESSURE-FIX.md)** for details on the fix
- Health checks run every 5 minutes and will log warnings if thresholds exceeded

## Extension System

Ops Defender provides **two extensibility points** that allow external code to customize behavior without modifying the core system:

1. **RequestPreHandler** - Intercept requests **before** processing (early bypass)
2. **PatternAnalyzer** - Inject custom pattern detection **during** deferred analysis (NEW)

### Extension Point 1: RequestPreHandler (Pre-Request Bypass)

Allows external code to intercept and process requests before the core defense logic executes. This enables building custom filtering logic without modifying the core system.

### Use Cases

The extension system enables various custom behaviors. Examples include:
- Geographic-based request handling
- Custom authentication integrations
- Request transformation or enrichment

### How It Works

**Extension Execution Flow:**

1. Request arrives at `/check` endpoint
2. **Pre-handlers invoked** in registration order (BEFORE any core processing)
3. If any pre-handler returns `ShouldBypass=true`:
   - Request bypasses all core logic (no tracking, no analysis, no blocking)
   - HTTP 200 (allow) returned immediately
   - Reason logged for debugging
4. If all pre-handlers pass (or none registered):
   - Normal core processing continues (pattern matching, blocking, etc.)

**Key Characteristics:**
- **Zero core code modifications** required
- **Fail-open by default** - extension errors don't block requests
- **Performance-optimized** - minimal lock contention
- **Ordered execution** - handlers run in registration order
- **Duplicate prevention** - same extension can't be registered twice

### Creating an Extension

**Public API:** Extensions are implemented using the **public `pkg/extensions` and `pkg/config` packages**, which can be imported by any external Go module.

```go
// Import the public packages
import (
    "github.com/ops/defender/pkg/extensions"
    "github.com/ops/defender/pkg/config"  // Configuration types
)

// Implement the RequestPreHandler interface
type RequestPreHandler interface {
    // PreHandleRequest inspects a request and decides whether to bypass core processing
    PreHandleRequest(request RequestInfo) (PreHandlerResult, error)
    
    // Name returns a unique identifier for this extension
    Name() string
}

type RequestInfo struct {
    IP        string              // Client IP address
    URI       string              // Requested URI
    UserAgent string              // User-Agent header
    Headers   map[string][]string // All HTTP headers
    Method    string              // HTTP method
}

type PreHandlerResult struct {
    ShouldBypass bool   // If true, skip all core processing
    Reason       string // Optional reason for logging
}
```

**Example Extension:**

```go
package myextension

import "github.com/ops/defender/pkg/extensions"

type CustomFilter struct {
    allowedIPs map[string]bool
}

func NewCustomFilter(ips []string) *CustomFilter {
    allowed := make(map[string]bool)
    for _, ip := range ips {
        allowed[ip] = true
    }
    return &CustomFilter{allowedIPs: allowed}
}

func (f *CustomFilter) Name() string {
    return "custom-filter"
}

func (f *CustomFilter) PreHandleRequest(req extensions.RequestInfo) (extensions.PreHandlerResult, error) {
    // Check if IP should bypass
    if f.allowedIPs[req.IP] {
        return extensions.PreHandlerResult{
            ShouldBypass: true,
            Reason:       "custom filter allowlist",
        }, nil
    }
    
    // Continue normal processing
    return extensions.PreHandlerResult{ShouldBypass: false}, nil
}
```

### Registering Extensions

Extensions are registered with the `Defender` instance using `RegisterExtension()`:

```go
package main

import (
    "github.com/ops/defender/internal/defender"
    "myextension"
)

func main() {
    // Create defender
    d := defender.NewDefender(defender.DefenderOptions{...})
    
    // Create and register extension
    filter := myextension.NewCustomFilter([]string{"10.0.0.1", "192.168.1.1"})
    d.RegisterExtension(filter)
    
    // Start server...
}
```

**Registration Notes:**
- Extensions can be registered **at any time** (thread-safe)
- Duplicate registrations (same `Name()`) are **ignored with warning**
- Nil extensions are **ignored with warning**
- Extensions with empty names are **ignored with warning**

### Extension Guidelines

**Performance Considerations:**
- Keep `PreHandleRequest()` **fast** - it runs on the critical request path
- Avoid blocking I/O or heavy computation
- Pre-load any required data during extension initialization
- Use in-memory lookups (maps, caches) instead of database queries

**Error Handling:**
- **Fail-open**: Errors don't block requests (logged and ignored)
- Return meaningful error messages for debugging
- Don't panic - use proper error returns

**Thread Safety:**
- `PreHandleRequest()` may be called **concurrently** from multiple goroutines
- Ensure all shared state is properly synchronized
- Read-only data structures are preferred

**Logging:**
- Bypass decisions are **automatically logged** by core system
- Add custom logging inside your extension if needed
- Use structured logging for better observability

### Extension Development Workflow

**Recommended pattern for private extensions:**

1. **Separate repository** for extension code (e.g., `ops-defender-extensions`)
2. **Import core types** from `github.com/ops/defender/pkg/extensions`
3. **Unit test** extension logic independently
4. **Integration test** with Ops Defender using multi-root workspace (see dev container guide)
5. **Register extension** in `main.go` or via plugin pattern

**Example Multi-Root Workspace Setup:**

```bash
# Clone both repositories
git clone https://github.com/luisgizirian/ops-defender.git
git clone https://github.com/your-org/ops-defender-extensions.git

# Create workspace
# File > Add Folder to Workspace (add both folders)
# File > Save Workspace As... → ops-defender-workspace.code-workspace

# Use devcontainer from ops-defender repo
# Extensions can reference core types via Go modules
```

See [.devcontainer/README.md](.devcontainer/README.md) for comprehensive multi-repo development setup.

### Extension Observability

**Logs:**
- Extension registration: `Registered extension: <name> (total extensions: N)`
- Extension errors: `Extension '<name>' returned error, continuing: <error>`
- Bypass decisions: `Request bypassed by extension '<name>': IP=..., URI=..., Reason=...`

**Metrics:**
- Bypassed requests **don't appear** in `total_requests` or any blocking metrics
- Use custom metrics in your extension if tracking is needed

**Debugging:**
- Check logs for extension registration confirmation
- Verify `Name()` returns unique identifier
- Test extension logic independently with unit tests
- Use `log.Printf()` inside extension for temporary debugging

### Extension Security

**Important Security Considerations:**

- **Trust boundary**: Extensions run with **full Ops Defender privileges**
- **Input validation**: Always validate `RequestInfo` data before use
- **Allowlist carefully**: Bypassed requests skip ALL security checks
- **Audit extensions**: Review extension code before production deployment
- **Minimize bypass**: Only bypass when absolutely necessary

**Best Practices:**
- Use **strict matching** (exact IP, not IP ranges if possible)
- **Log all bypass decisions** for audit trail
- **Limit extension scope** to specific well-defined use cases
- **Test thoroughly** including malicious input scenarios

### Extension Point 2: PatternAnalyzer (Deferred Analysis)

**NEW:** Allows custom pattern detection logic to run during deferred analysis, after requests are logged but before the block decision is made.

**Use Cases:**
- Custom attack pattern detection (SQL injection, XSS, etc.)
- Domain-specific security rules
- Machine learning-based anomaly detection
- Integration with threat intelligence feeds

**Execution Flow:**

1. IP reaches analysis threshold (default: 5 requests)
2. Analysis worker invoked with request history
3. **Built-in checks run** (path traversal, nesting, etc.)
4. **PatternAnalyzers invoked** in priority order
5. First analyzer returning `IsSuspicious=true` triggers block
6. IP blocked for configured duration

**Interface Definition:**

```go
// Import the public extensions package
import "github.com/ops/defender/pkg/extensions"

type PatternAnalyzer interface {
    // AnalyzePattern inspects request history and returns suspicion verdict
    AnalyzePattern(ctx AnalysisContext) (AnalysisResult, error)
    
    // Name returns unique identifier
    Name() string
    
    // Priority returns execution order (0=highest, 100=lowest, default 50)
    Priority() int
}

type AnalysisContext struct {
    IP           string        // IP being analyzed
    RequestLogs  []RequestLog  // All logged requests from this IP
    RequestCount int           // Total request count
    FirstSeen    time.Time     // First request timestamp
    LastSeen     time.Time     // Last request timestamp
}

type RequestLog struct {
    URI           string
    Timestamp     time.Time
    UserAgent     string
    IsWhitelisted bool
    Method        string
}

type AnalysisResult struct {
    IsSuspicious  bool    // True if suspicious pattern detected
    Reason        string  // Human-readable reason
    SuspiciousURI string  // Specific URI that triggered detection
    Confidence    float64 // Confidence score 0.0-1.0 (optional)
}
```

**Example: SQL Injection Detector**

```go
package myanalyzer

import (
    "regexp"
    "github.com/ops/defender/pkg/extensions"
)

type SQLInjectionDetector struct {
    patterns []*regexp.Regexp
}

func NewSQLInjectionDetector() *SQLInjectionDetector {
    return &SQLInjectionDetector{
        patterns: []*regexp.Regexp{
            regexp.MustCompile(`(?i)(union\s+select|union\s+all\s+select)`),
            regexp.MustCompile(`(?i)(select.*from|insert\s+into)`),
            // ... more patterns
        },
    }
}

func (d *SQLInjectionDetector) AnalyzePattern(ctx extensions.AnalysisContext) (extensions.AnalysisResult, error) {
    for _, log := range ctx.RequestLogs {
        for _, pattern := range d.patterns {
            if pattern.MatchString(log.URI) {
                return extensions.AnalysisResult{
                    IsSuspicious:  true,
                    Reason:        "SQL injection pattern detected",
                    SuspiciousURI: log.URI,
                    Confidence:    0.95,
                }, nil
            }
        }
    }
    return extensions.AnalysisResult{IsSuspicious: false}, nil
}

func (d *SQLInjectionDetector) Name() string { return "sql-injection-detector" }
func (d *SQLInjectionDetector) Priority() int { return 10 } // High priority
```

**Registering Pattern Analyzers:**

```go
package main

import (
    "github.com/ops/defender/internal/defender"
    "myanalyzer"
)

func main() {
    d := defender.NewDefender(defender.DefenderOptions{...})
    
    // Register analyzer
    sqlDetector := myanalyzer.NewSQLInjectionDetector()
    d.RegisterPatternAnalyzer(sqlDetector)
    
    // Start server...
}
```

**Priority System:**

Analyzers are executed in priority order (lower value = higher priority):

- **0-10**: Critical checks (run first)
- **11-50**: Standard checks
- **51-100**: Exploratory checks (run last)

Use priority to ensure high-confidence analyzers run before exploratory ones.

**Performance Guidelines:**

- **Target execution time**: <100ms per analysis
- **Async execution**: Runs in analysis worker (not on request path)
- **No blocking I/O**: Avoid database calls or external APIs
- **In-memory processing**: Use pre-compiled patterns, local caches
- **Early exit**: Return suspicious=true as soon as high-confidence match found

**Error Handling:**

- **Fail-open**: Errors are logged but don't block analysis
- **Isolation**: Analyzer errors don't affect other analyzers or core logic
- **Observability**: All errors logged with analyzer name and IP

**Testing:**

```bash
# Send legitimate requests
for i in {1..5}; do
  curl -H "X-Real-IP: 10.0.0.1" \
       -H "X-Original-URI: /api/users?id=123" \
       http://localhost:8080/check
done

# Send malicious requests (SQL injection)
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
Request pattern flagged by analyzer 'sql-injection-detector': IP=10.0.0.2, Reason=SQL injection pattern detected, URI=/api/users?id=1' OR '1'='1, Confidence=0.95
IP marked as suspicious and blocked: 10.0.0.2
```

**Complete Example:**

See [examples/sql-injection-detector/](examples/sql-injection-detector/) for a full implementation with confidence scoring and multiple pattern types.

**Best Practices:**
- Use **strict matching** (exact IP, not IP ranges if possible)
- **Log all bypass decisions** for audit trail
- **Limit extension scope** to specific well-defined use cases
- **Test thoroughly** including malicious input scenarios

## Documentation

- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Development guide and getting started
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Production deployment guide
- **[ROLLBACK.md](ROLLBACK.md)** - Fast rollback procedures for production
- **[DDOS-DEFENSE.md](DDOS-DEFENSE.md)** - DDoS protection analysis
- **[MEMORY-PRESSURE-FIX.md](MEMORY-PRESSURE-FIX.md)** - Memory pressure bug fix (40,000 requests issue)
- **[.devcontainer/README.md](.devcontainer/README.md)** - Dev container comprehensive guide
- **[examples/MONITORING.md](examples/MONITORING.md)** - Complete monitoring and visualization guide
- **[examples/AZURE-INSIGHTS.md](examples/AZURE-INSIGHTS.md)** - Azure Application Insights integration
- **[examples/grafana-dashboard.json](examples/grafana-dashboard.json)** - Grafana dashboard template
- **[examples/prometheus.yml](examples/prometheus.yml)** - Prometheus configuration example

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute.

## Support

For monitoring setup issues or questions:
- **GitHub Issues**: https://github.com/luisgizirian/ops-defender/issues
- Check [MONITORING.md](MONITORING.md) for detailed troubleshooting
- Review [AZURE-INSIGHTS.md](AZURE-INSIGHTS.md) for Azure-specific issues
- See main [README.md](../README.md) for general documentation
- Tag monitoring-related issues with `monitoring` label
