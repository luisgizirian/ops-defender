# Private Extension Repository Example

This directory demonstrates the structure of a **private extension repository** that extends Ops Defender without forking or modifying the core.

## Repository Structure

```
your-company/ops-defender-extensions/
├── go.mod                      # Depends on public ops-defender core
├── go.sum
├── README.md                   # This file
├── cmd/
│   └── ops-defender-extended/
│       └── main.go             # Entry point with extension registration
├── patterns/
│   ├── internal_api.go         # Company-specific suspicious patterns
│   ├── critical_paths.go       # High-priority security patterns
│   └── patterns_test.go        # Tests for pattern providers
├── rules/
│   ├── rate_limiting.go        # Custom blocking rules
│   ├── geo_blocking.go         # Geography-based blocking
│   └── rules_test.go           # Tests for rule providers
├── whitelists/
│   ├── cdn_paths.go            # CDN whitelist
│   ├── monitoring.go           # Monitoring endpoint whitelist
│   └── whitelists_test.go      # Tests for whitelist providers
└── Dockerfile                  # Docker build for extended version
```

## Quick Start

### 1. Create Private Repository

```bash
# Create new repository
mkdir ops-defender-extensions
cd ops-defender-extensions

# Initialize Go module
go mod init your-company/ops-defender-extensions

# Add dependency on public core
go get github.com/ops/defender@latest
```

### 2. Create Extension Provider

```go
// patterns/internal_api.go
package patterns

import "github.com/ops/defender/extension-points"

type InternalAPIPatternProvider struct{}

func (i *InternalAPIPatternProvider) GetPatterns() []string {
    return []string{
        `/internal-api`,           // Block internal API access
        `/company-admin`,          // Company-specific admin paths
        `/secret-dashboard`,       // Sensitive dashboards
        `\.backup$`,               // Backup file attempts
        `/actuator/.*shutdown`,    // Dangerous actuator endpoints
    }
}

func (i *InternalAPIPatternProvider) GetName() string {
    return "Internal API Protection"
}

func (i *InternalAPIPatternProvider) GetPriority() int {
    return 50  // Medium-high priority
}
```

### 3. Create Main Entry Point

```go
// cmd/ops-defender-extended/main.go
package main

import (
    "log"
    "os"
    "strconv"
    "time"

    "github.com/ops/defender/extension-points"
    "github.com/ops/defender/internal/config"
    "github.com/ops/defender/internal/defender"
    "github.com/ops/defender/internal/storage"
    
    // Import your private extensions
    "your-company/ops-defender-extensions/patterns"
    "your-company/ops-defender-extensions/rules"
    "your-company/ops-defender-extensions/whitelists"
)

func main() {
    // Load configuration
    cfg := config.Load()
    
    // Initialize storage
    var store storage.Storage
    if cfg.RedisURL != "" {
        var err error
        store, err = storage.NewRedisStorage(cfg.RedisURL, cfg.BlockDuration)
        if err != nil {
            log.Fatalf("Failed to connect to Redis: %v", err)
        }
    } else {
        store = storage.NewMemoryStorage(cfg.BlockDuration)
    }
    
    // Create extension registry
    registry := extensions.NewExtensionRegistry()
    
    // Register custom pattern providers
    registry.RegisterPatternProvider(&patterns.InternalAPIPatternProvider{})
    registry.RegisterPatternProvider(&patterns.CriticalSecurityPatternProvider{})
    
    // Register custom blocking rules
    registry.RegisterBlockingRuleProvider(&rules.RateLimitingRule{})
    registry.RegisterBlockingRuleProvider(&rules.GeoBlockingRule{})
    
    // Register custom whitelists
    registry.RegisterWhitelistProvider(&whitelists.CDNWhitelistProvider{})
    registry.RegisterWhitelistProvider(&whitelists.MonitoringWhitelistProvider{})
    
    log.Printf("Loaded extensions:")
    log.Printf("  - %d pattern providers", len(registry.GetAllPatterns()))
    log.Printf("  - %d blocking rule providers", len(registry.GetAllBlockingRules()))
    log.Printf("  - %d whitelist providers", len(registry.GetAllWhitelistPatterns()))
    
    // Create defender with extensions
    d := defender.NewDefender(defender.DefenderOptions{
        AnalysisThreshold:    cfg.AnalysisThreshold,
        BlockDuration:        cfg.BlockDuration,
        Storage:              store,
        MaxTrackedIPs:        cfg.MaxTrackedIPs,
        EvictionBatchPct:     0.10,
        EvictionThresholdPct: 0.93,
        SimulationMode:       cfg.SimulationMode,
        ExtensionRegistry:    registry,  // Pass extension registry
    })
    
    // Continue with normal server setup...
    log.Printf("Starting Ops Defender (Extended) on port %s", cfg.Port)
    // ... HTTP server setup
}
```

### 4. Build and Deploy

```bash
# Build extended version
go build -o ops-defender-extended ./cmd/ops-defender-extended

# Run
./ops-defender-extended

# Or with Docker
docker build -t your-company/ops-defender-extended .
docker run -p 8080:8080 your-company/ops-defender-extended
```

## Example Extensions

### Pattern Provider

```go
// patterns/critical_paths.go
package patterns

type CriticalSecurityPatternProvider struct{}

func (c *CriticalSecurityPatternProvider) GetPatterns() []string {
    return []string{
        `/auth/bypass`,                    // Auth bypass attempts
        `/__debug__`,                      // Django debug
        `/\.aws/credentials`,              // AWS credentials
        `/config/.*password`,              // Config with passwords
        `system\(.*rm.*-rf`,               // Dangerous system commands
    }
}

func (c *CriticalSecurityPatternProvider) GetName() string {
    return "Critical Security Patterns"
}

func (c *CriticalSecurityPatternProvider) GetPriority() int {
    return 100  // High priority - checked first
}
```

### Blocking Rule Provider

```go
// rules/rate_limiting.go
package rules

import "github.com/ops/defender/extension-points"

type RateLimitingRule struct{}

func (r *RateLimitingRule) ShouldBlock(
    ip string,
    requestCount int,
    requestLogs []extensions.RequestLogInfo,
) (bool, string) {
    // Block if more than 100 requests
    if requestCount > 100 {
        return true, "exceeded rate limit of 100 requests"
    }
    
    // Block if multiple failed auth attempts
    failedAuths := 0
    for _, log := range requestLogs {
        if strings.Contains(log.URI, "/auth/login") {
            failedAuths++
        }
    }
    
    if failedAuths >= 5 {
        return true, "multiple failed authentication attempts"
    }
    
    return false, ""
}

func (r *RateLimitingRule) GetName() string {
    return "Custom Rate Limiting"
}

func (r *RateLimitingRule) GetPriority() int {
    return 0
}
```

### Whitelist Provider

```go
// whitelists/cdn_paths.go
package whitelists

type CDNWhitelistProvider struct{}

func (c *CDNWhitelistProvider) GetWhitelistPatterns() []string {
    return []string{
        `^/cdn/.*`,                              // CDN content
        `^/static/.*\.(js|css|png|jpg|svg)$`,    // Static assets
        `^/public/.*`,                           // Public directory
        `^/api/v1/health$`,                      // Health checks
        `^/.well-known/.*`,                      // Well-known URIs
    }
}

func (c *CDNWhitelistProvider) GetName() string {
    return "CDN Whitelist"
}

func (c *CDNWhitelistProvider) GetPriority() int {
    return 100  // High priority - check first
}
```

## Testing Extensions

### Unit Tests

```go
// patterns/patterns_test.go
package patterns

import "testing"

func TestInternalAPIPatternProvider(t *testing.T) {
    provider := &InternalAPIPatternProvider{}
    
    patterns := provider.GetPatterns()
    if len(patterns) == 0 {
        t.Error("Expected patterns, got none")
    }
    
    // Verify specific patterns exist
    found := false
    for _, p := range patterns {
        if p == `/internal-api` {
            found = true
            break
        }
    }
    
    if !found {
        t.Error("Expected /internal-api pattern")
    }
}
```

### Integration Tests

```go
// Test with full defender
func TestExtensionsIntegration(t *testing.T) {
    registry := extensions.NewExtensionRegistry()
    registry.RegisterPatternProvider(&InternalAPIPatternProvider{})
    
    defender := defender.NewDefender(defender.DefenderOptions{
        ExtensionRegistry: registry,
        // ... other options
    })
    
    // Test that custom patterns work
    // ... test implementation
}
```

## Deployment

### Docker

```dockerfile
# Dockerfile
FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o ops-defender-extended ./cmd/ops-defender-extended

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/ops-defender-extended .

EXPOSE 8080
CMD ["./ops-defender-extended"]
```

### Kubernetes

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ops-defender-extended
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ops-defender-extended
  template:
    metadata:
      labels:
        app: ops-defender-extended
    spec:
      containers:
      - name: ops-defender
        image: your-company/ops-defender-extended:latest
        ports:
        - containerPort: 8080
        env:
        - name: REDIS_URL
          value: "redis://redis-service:6379/0"
        - name: ANALYSIS_THRESHOLD
          value: "5"
        - name: BLOCK_DURATION
          value: "60"
```

## Benefits

✅ **No forking** - Extensions in separate repository  
✅ **Easy updates** - Pull latest core, rebuild extended version  
✅ **Private code** - Keep company-specific logic private  
✅ **Clean separation** - Core stays generic, extensions add specifics  
✅ **Testable** - Test extensions independently  

## Maintenance

### Updating Core Dependency

```bash
# Update to latest public core
go get github.com/ops/defender@latest
go mod tidy

# Test
go test ./...

# Rebuild
go build ./cmd/ops-defender-extended
```

### Version Pinning

```go
// go.mod
module your-company/ops-defender-extensions

go 1.25

require (
    github.com/ops/defender v1.2.3  // Pin to specific version
)
```

## Support

- **Core issues**: https://github.com/ops/defender/issues
- **Extension documentation**: See [EXTENSIBILITY.md](https://github.com/ops/defender/blob/main/EXTENSIBILITY.md)
- **Examples**: See [examples/extensions/](https://github.com/ops/defender/tree/main/examples/extensions)
