# Staging Example: Ops Defender with IP Allowlist Extension

This example demonstrates a **production-ready staging configuration** that combines the core Ops Defender system with an IP allowlist extension. It showcases how to build a custom deployment with private extension logic while keeping the core system unchanged.

## Overview

The staging example includes:
- **Core Ops Defender** - All standard defense features (pattern detection, blocking, reporting)
- **IP Allowlist Extension** - Custom extension that bypasses defense checks for trusted IPs and CIDR ranges
- **Production-ready configuration** - Error logging, telemetry, monitoring endpoints
- **Docker support** - Both single-repo and multi-repo Docker builds

## Features

### IP Allowlist Extension

The allowlist extension supports:
- **Individual IP addresses** - Both IPv4 and IPv6 (e.g., `192.168.1.1`, `2001:db8::1`)
- **CIDR ranges** - Subnet ranges (e.g., `10.0.0.0/8`, `66.249.64.0/19`)
- **Fast lookups** - In-memory hash maps and range checking
- **Zero core modifications** - Extension runs independently via the `RequestPreHandler` interface

### How It Works

1. Request arrives at `/check` endpoint
2. **Allowlist extension checks IP first** (before any core processing)
3. If IP matches allowlist:
   - Request bypasses all defense logic
   - Returns HTTP 200 immediately
   - No tracking, no analysis, no blocking
4. If IP not in allowlist:
   - Normal Ops Defender processing continues
   - Pattern detection, blocking, etc.

## Configuration

### Allowlist Configuration

The allowlist is configured via JSON file (`allowlist.json`):

```json
{
  "allowed_ips": [
    "201.216.223.105",
    "66.249.64.0/19"
  ]
}
```

**Supported formats:**
- Individual IPv4: `"192.168.1.1"`
- Individual IPv6: `"2001:db8::1"`
- CIDR range IPv4: `"10.0.0.0/8"`, `"172.16.0.0/12"`, `"66.249.64.0/19"`
- CIDR range IPv6: `"2001:db8::/32"`

### Environment Variables

All standard Ops Defender environment variables are supported:

**Core Settings:**
- `PORT` - HTTP server port (default: `8080`)
- `ANALYSIS_THRESHOLD` - Requests before analysis (default: `5`)
- `BLOCK_DURATION` - Block duration in minutes (default: `60`)
- `MAX_TRACKED_IPS` - Memory limit (default: `10000`)
- `REDIS_URL` - Redis connection string (optional)
- `SIMULATION_MODE` - Testing mode (default: `false`)

**Extension Settings:**
- `ALLOWLIST_CONFIG` - Path to allowlist JSON file (default: `/etc/ops-defender/allowlist.json`)

**Monitoring:**
- `APPINSIGHTS_ENABLED` - Enable Azure telemetry (default: `false`)
- `APPINSIGHTS_INSTRUMENTATION_KEY` - Azure App Insights key

**Email Reporting:**
- `EMAIL_ENABLED` - Enable email reports (default: `false`)
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` - SMTP configuration
- `EMAIL_FROM`, `EMAIL_TO` - Email addresses

## Usage

### Local Development

```bash
# Navigate to staging example
cd examples/staging

# Build
go build -o ops-defender-staging .

# Run with default config (looks for /etc/ops-defender/allowlist.json)
./ops-defender-staging

# Or specify custom allowlist location
ALLOWLIST_CONFIG=./allowlist.json ./ops-defender-staging

# With custom settings
PORT=9090 \
ANALYSIS_THRESHOLD=3 \
BLOCK_DURATION=120 \
ALLOWLIST_CONFIG=./allowlist.json \
./ops-defender-staging
```

### Docker Build (Single Repository)

```bash
# From repository root
docker build -f examples/staging/Dockerfile -t ops-defender-staging .

# Run
docker run -p 8080:8080 ops-defender-staging

# With custom allowlist (mount as volume)
docker run -p 8080:8080 \
  -v $(pwd)/custom-allowlist.json:/etc/ops-defender/allowlist.json \
  ops-defender-staging
```

### Docker Build (Multi-Root Workspace)

For development scenarios where you have ops-defender and a separate extension repository:

```bash
# Directory structure:
# workspace/
# ├── ops-defender/          # Core repository
# └── ops-defender-extensions/  # Private extension repo (optional)

# Build from workspace parent directory
docker build -f ops-defender/examples/staging/Dockerfile.multiroot \
  -t ops-defender-staging .
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data

  ops-defender:
    build:
      context: .
      dockerfile: examples/staging/Dockerfile
    ports:
      - "8080:8080"
    environment:
      - REDIS_URL=redis://redis:6379/0
      - ANALYSIS_THRESHOLD=5
      - BLOCK_DURATION=60
      - ALLOWLIST_CONFIG=/etc/ops-defender/allowlist.json
    depends_on:
      - redis
    volumes:
      # Optional: mount custom allowlist
      - ./custom-allowlist.json:/etc/ops-defender/allowlist.json

volumes:
  redis-data:
```

Run with:
```bash
docker-compose up
```

## Testing

### Test Allowlisted IP

```bash
# IP in allowlist - should return 200 and bypass all checks
curl -H "X-Real-IP: 201.216.223.105" \
     -H "X-Original-URI: /../../etc/passwd" \
     http://localhost:8080/check
# Expected: HTTP 200 (allowed) - even though URI is malicious

# IP in CIDR range - should also bypass
curl -H "X-Real-IP: 66.249.64.100" \
     -H "X-Original-URI: /malicious/path" \
     http://localhost:8080/check
# Expected: HTTP 200 (allowed)
```

### Test Non-Allowlisted IP

```bash
# Send 5+ malicious requests from non-allowlisted IP
for i in {1..6}; do
  curl -H "X-Real-IP: 192.168.1.100" \
       -H "X-Original-URI: /../../etc/passwd" \
       http://localhost:8080/check
  sleep 0.5
done
# Expected: First 5 return 200, then 403 (blocked)
```

### Check Logs

```bash
# Should see extension registration
Registered extension: ip-allowlist (total extensions: 1)
Registered IP allowlist extension with 2 entries

# Should see bypass logs for allowlisted IPs
Request bypassed by extension 'ip-allowlist': IP=201.216.223.105, URI=/../../etc/passwd, Reason=IP in allowlist
```

## Monitoring

All standard Ops Defender monitoring endpoints are available:

```bash
# Health check
curl http://localhost:8080/health

# Statistics (bypassed IPs won't appear in blocked count)
curl http://localhost:8080/stats | jq

# Prometheus metrics
curl http://localhost:8080/metrics

# Time-series data
curl "http://localhost:8080/timeseries?period=24&interval=1h" | jq

# Real-time events (Server-Sent Events)
curl -N http://localhost:8080/events
```

## Customization

### Adding More Allowlist Entries

Edit `allowlist.json`:

```json
{
  "allowed_ips": [
    "201.216.223.105",
    "66.249.64.0/19",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.1.100",
    "2001:db8::1"
  ]
}
```

Restart the service to apply changes.

### Extending the Allowlist Logic

Modify `allowlist.go` to add more sophisticated matching:

```go
// Example: Add User-Agent filtering
func (e *AllowlistExtension) PreHandleRequest(req extensions.RequestInfo) (extensions.PreHandlerResult, error) {
    // Check IP allowlist
    if e.allowedIPs[req.IP] {
        return extensions.PreHandlerResult{
            ShouldBypass: true,
            Reason:       "IP in allowlist",
        }, nil
    }
    
    // Add custom logic here
    if strings.Contains(req.UserAgent, "Googlebot") && e.allowedIPs["googlebot"] {
        return extensions.PreHandlerResult{
            ShouldBypass: true,
            Reason:       "Googlebot user agent",
        }, nil
    }
    
    return extensions.PreHandlerResult{ShouldBypass: false}, nil
}
```

## Production Deployment

### Security Recommendations

1. **Restrict allowlist** - Only add IPs that truly need bypass (internal services, monitoring, etc.)
2. **Use CIDR ranges carefully** - Smaller ranges are safer (e.g., `/24` instead of `/8`)
3. **Audit bypass decisions** - Monitor logs for `Request bypassed by extension` messages
4. **Separate sensitive IPs** - Keep allowlist config in secure location
5. **Rotate regularly** - Review and update allowlist periodically

### File Permissions

```bash
# Ensure allowlist config is read-only
chmod 600 /etc/ops-defender/allowlist.json
chown root:root /etc/ops-defender/allowlist.json
```

### Kubernetes Deployment

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ops-defender-allowlist
data:
  allowlist.json: |
    {
      "allowed_ips": [
        "201.216.223.105",
        "66.249.64.0/19"
      ]
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ops-defender
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: ops-defender
        image: ops-defender-staging:latest
        ports:
        - containerPort: 8080
        env:
        - name: REDIS_URL
          value: "redis://redis-service:6379/0"
        - name: ALLOWLIST_CONFIG
          value: "/etc/ops-defender/allowlist.json"
        volumeMounts:
        - name: allowlist
          mountPath: /etc/ops-defender
      volumes:
      - name: allowlist
        configMap:
          name: ops-defender-allowlist
```

## Troubleshooting

### Allowlist Not Working

**Check logs for:**
```
Registered IP allowlist extension with N entries
```

If missing, check:
1. `ALLOWLIST_CONFIG` environment variable points to correct file
2. JSON file exists and is readable
3. JSON format is valid (use `jq . < allowlist.json` to validate)

### IP Still Getting Blocked

**Debug steps:**
1. Check exact IP format in logs vs. allowlist
2. IPv6 addresses must match exactly (no compression differences)
3. CIDR ranges must be valid (`66.249.64.0/19`, not `66.249.64.1/19`)
4. Check logs for bypass messages

### Extension Not Loading

**Common issues:**
1. File permissions - ensure readable by process user
2. JSON syntax errors - validate with `jq`
3. File path incorrect - check `ALLOWLIST_CONFIG` value

## Performance

The allowlist extension is optimized for minimal overhead:
- **Individual IPs**: O(1) hash map lookup (~50-100ns)
- **CIDR ranges**: O(n) range check (~200-500ns per range)
- **Total overhead**: < 1μs for typical configurations

## Related Documentation

- **[Main README](../../README.md)** - Core Ops Defender documentation
- **[Extension System Guide](../../README.md#extension-system)** - Extension architecture and API
- **[EXTENSION-EXAMPLE.md](../EXTENSION-EXAMPLE.md)** - Advanced extension patterns
- **[External Extension Example](../external-extension/README.md)** - Public API usage
- **[DEPLOYMENT.md](../../DEPLOYMENT.md)** - Production deployment guide
- **[.devcontainer/README.md](../../.devcontainer/README.md)** - Multi-root workspace development

## License

This example is part of the Ops Defender project and is licensed under the MIT License.
