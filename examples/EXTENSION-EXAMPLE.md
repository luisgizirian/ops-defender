# Extension System Example

This example demonstrates how to create and register a custom extension with Ops Defender.

## Simple Request Logger Extension

This is a "hello world" style extension that logs custom information about requests.

```go
package main

import (
    "log"
    "net/http"
    "os"
    "sync"
    "time"

    "github.com/ops/defender/internal/config"
    "github.com/ops/defender/internal/defender"
    "github.com/ops/defender/internal/extensions"
    "github.com/ops/defender/internal/storage"
)

// RequestLoggerExtension logs additional request information
// Useful for custom analytics or debugging
type RequestLoggerExtension struct {
    mu           sync.Mutex
    requestCount map[string]int
    logVerbose   bool
}

func NewRequestLoggerExtension(verbose bool) *RequestLoggerExtension {
    return &RequestLoggerExtension{
        requestCount: make(map[string]int),
        logVerbose:   verbose,
    }
}

func (e *RequestLoggerExtension) Name() string {
    return "request-logger"
}

func (e *RequestLoggerExtension) PreHandleRequest(req extensions.RequestInfo) (extensions.PreHandlerResult, error) {
    // Count requests per IP
    e.mu.Lock()
    e.requestCount[req.IP]++
    count := e.requestCount[req.IP]
    e.mu.Unlock()

    // Log request details if verbose mode enabled
    if e.logVerbose {
        log.Printf("[RequestLogger] IP=%s, URI=%s, Method=%s, Count=%d",
            req.IP, req.URI, req.Method, count)
    }

    // Continue normal processing (don't bypass)
    return extensions.PreHandlerResult{ShouldBypass: false}, nil
}

// GetStats returns custom statistics
func (e *RequestLoggerExtension) GetStats() map[string]int {
    e.mu.Lock()
    defer e.mu.Unlock()
    
    stats := make(map[string]int)
    for ip, count := range e.requestCount {
        stats[ip] = count
    }
    return stats
}

func main() {
    // Load configuration
    cfg := config.LoadConfig()

    // Create storage
    var store storage.Storage
    if cfg.RedisURL != "" {
        store = storage.NewRedisStorage(cfg.RedisURL, cfg.BlockDuration)
    } else {
        store = storage.NewMemoryStorage(cfg.BlockDuration)
    }

    // Create defender
    d := defender.NewDefender(defender.DefenderOptions{
        AnalysisThreshold:    cfg.AnalysisThreshold,
        BlockDuration:        cfg.BlockDuration,
        Storage:              store,
        MaxTrackedIPs:        cfg.MaxTrackedIPs,
        EvictionBatchPct:     0.10,
        EvictionThresholdPct: 0.93,
        SimulationMode:       cfg.SimulationMode,
    })

    // Register request logger extension
    verbose := os.Getenv("LOG_VERBOSE") == "true"
    ext := NewRequestLoggerExtension(verbose)
    d.RegisterExtension(ext)
    log.Printf("Registered request logger extension (verbose: %v)", verbose)

    // Setup HTTP server
    http.HandleFunc("/check", d.CheckRequest)
    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("OK"))
    })
    http.HandleFunc("/stats", d.GetStats)
    http.HandleFunc("/report", d.GetReport)

    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }

    log.Printf("Starting Ops Defender with Request Logger Extension on port %s...", port)
    if err := http.ListenAndServe(":"+port, nil); err != nil {
        log.Fatalf("Server failed to start: %v", err)
    }
}
```

## Usage

### 1. Build and Run

```bash
# Enable verbose logging
export LOG_VERBOSE="true"

# Run with default settings
./ops-defender

# Or specify additional configuration
export ANALYSIS_THRESHOLD=5
export BLOCK_DURATION=60
export REDIS_URL=redis://localhost:6379/0
./ops-defender
```

### 2. Test the Extension

```bash
# Send some test requests
curl -H "X-Real-IP: 192.168.1.1" \
     -H "X-Original-URI: /api/data" \
     http://localhost:8080/check

curl -H "X-Real-IP: 192.168.1.2" \
     -H "X-Original-URI: /api/users" \
     http://localhost:8080/check

curl -H "X-Real-IP: 192.168.1.1" \
     -H "X-Original-URI: /api/products" \
     http://localhost:8080/check
```

### 3. Check Logs

```
Registered extension: request-logger (total extensions: 1)
Registered request logger extension (verbose: true)
Starting Ops Defender with Request Logger Extension on port 8080...

[RequestLogger] IP=192.168.1.1, URI=/api/data, Method=GET, Count=1
[RequestLogger] IP=192.168.1.2, URI=/api/users, Method=GET, Count=1
[RequestLogger] IP=192.168.1.1, URI=/api/products, Method=GET, Count=2
```

## Advanced Example: Custom Metrics Tracking

```go
// CustomMetricsExtension tracks custom metrics per URI pattern
type CustomMetricsExtension struct {
    mu      sync.Mutex
    metrics map[string]int
}

func NewCustomMetricsExtension() *CustomMetricsExtension {
    return &CustomMetricsExtension{
        metrics: make(map[string]int),
    }
}

func (e *CustomMetricsExtension) Name() string {
    return "custom-metrics"
}

func (e *CustomMetricsExtension) PreHandleRequest(req extensions.RequestInfo) (extensions.PreHandlerResult, error) {
    // Extract URI pattern (e.g., /api/* -> /api)
    pattern := strings.Split(req.URI, "/")
    if len(pattern) > 1 {
        category := "/" + pattern[1]
        
        e.mu.Lock()
        e.metrics[category]++
        e.mu.Unlock()
        
        log.Printf("[Metrics] Category=%s, Count=%d", category, e.metrics[category])
    }

    // Continue normal processing
    return extensions.PreHandlerResult{ShouldBypass: false}, nil
}

// Usage:
ext := NewCustomMetricsExtension()
d.RegisterExtension(ext)
```

## Multi-Extension Example

```go
// Register multiple extensions (executed in order)
logger := NewRequestLoggerExtension(true)
metrics := NewCustomMetricsExtension()

d.RegisterExtension(logger)   // Checked first - logs request details
d.RegisterExtension(metrics)  // Checked second - tracks URI patterns

// Execution flow:
// 1. Request logger logs IP, URI, method
// 2. Custom metrics tracks URI categories
// 3. Normal Ops Defender processing continues
```

## Configuration via Environment Variables

Add to your `.env` or environment:

```bash
# Core Ops Defender Settings
PORT=8080
ANALYSIS_THRESHOLD=5
BLOCK_DURATION=60
MAX_TRACKED_IPS=10000
REDIS_URL=redis://localhost:6379/0

# Extension Configuration
LOG_VERBOSE=true
METRICS_ENABLED=true
```

## Extension Best Practices

1. **Keep PreHandleRequest() Fast**
   - Use in-memory data structures (maps, slices)
   - Avoid database queries or external API calls
   - Pre-load configuration during initialization

2. **Handle Errors Gracefully**
   - Return meaningful error messages
   - Don't panic - use proper error returns
   - Extension errors fail-open (request continues)

3. **Thread Safety**
   - `PreHandleRequest()` may be called concurrently
   - Use read-only data or proper synchronization
   - Avoid shared mutable state

4. **Testing**
   - Unit test your extension logic independently
   - Integration test with Ops Defender
   - Benchmark performance impact

5. **Security**
   - Validate all inputs from `RequestInfo`
   - Be cautious with logging sensitive data
   - Consider performance impact of custom logging

## Deployment

For production deployments with private extensions, consider using multi-root workspace development (see [README.md](../README.md#extension-system)).

### Private Extension Repository Setup

Organizations often want to keep their custom logic (IP allowlists, business rules, etc.) separate from the core Ops Defender system. Here's how to set up a private extension repository:

**Requirements:**

1. **Separate Git Repository** for your private extensions:
   ```bash
   # Create new repository (GitHub, GitLab, Bitbucket, etc.)
   mkdir ops-defender-extensions
   cd ops-defender-extensions
   git init
   ```

2. **Go Module Initialization**:
   ```bash
   # Initialize as a Go module
   go mod init github.com/your-org/ops-defender-extensions
   
   # Add Ops Defender as dependency (for importing extension interfaces)
   go get github.com/luisgizirian/ops-defender
   ```

3. **Project Structure**:
   ```
   ops-defender-extensions/          # Your private repository
   ├── go.mod                         # Module definition
   ├── go.sum                         # Dependency checksums
   ├── README.md                      # Internal documentation
   ├── filters/                       # Example: IP filtering extension
   │   ├── ipfilter.go               # Extension implementation
   │   └── ipfilter_test.go          # Unit tests
   ├── config/                        # Configuration loading
   │   ├── config.go                 # Load allowlists, rules, etc.
   │   └── config_test.go
   └── cmd/
       └── ops-defender-custom/       # Custom build with extensions
           └── main.go                # Entry point that registers extensions
   ```

4. **Extension Implementation** (example: `filters/ipfilter.go`):
   ```go
   package filters
   
   import (
       "github.com/luisgizirian/ops-defender/internal/extensions"
   )
   
   type IPFilter struct {
       allowedIPs map[string]bool
   }
   
   func NewIPFilter(ips []string) *IPFilter {
       allowed := make(map[string]bool)
       for _, ip := range ips {
           allowed[ip] = true
       }
       return &IPFilter{allowedIPs: allowed}
   }
   
   func (f *IPFilter) Name() string {
       return "ip-filter"
   }
   
   func (f *IPFilter) PreHandleRequest(req extensions.RequestInfo) (extensions.PreHandlerResult, error) {
       if f.allowedIPs[req.IP] {
           return extensions.PreHandlerResult{
               ShouldBypass: true,
               Reason:       "IP in allowlist",
           }, nil
       }
       return extensions.PreHandlerResult{ShouldBypass: false}, nil
   }
   ```

5. **Configuration Loading** (example: `config/config.go`):
   ```go
   package config
   
   import (
       "encoding/json"
       "os"
   )
   
   type ExtensionConfig struct {
       AllowedIPs []string `json:"allowed_ips"`
   }
   
   func LoadConfig(path string) (*ExtensionConfig, error) {
       data, err := os.ReadFile(path)
       if err != nil {
           return nil, err
       }
       
       var cfg ExtensionConfig
       if err := json.Unmarshal(data, &cfg); err != nil {
           return nil, err
       }
       
       return &cfg, nil
   }
   ```

6. **Custom Main Application** (`cmd/ops-defender-custom/main.go`):
   ```go
   package main
   
   import (
       "log"
       "net/http"
       "os"
       
       // Core Ops Defender
       "github.com/luisgizirian/ops-defender/internal/config"
       "github.com/luisgizirian/ops-defender/internal/defender"
       "github.com/luisgizirian/ops-defender/internal/storage"
       
       // Your private extensions
       extconfig "github.com/your-org/ops-defender-extensions/config"
       "github.com/your-org/ops-defender-extensions/filters"
   )
   
   func main() {
       // Load core Ops Defender configuration
       cfg := config.LoadConfig()
       
       // Create storage
       var store storage.Storage
       if cfg.RedisURL != "" {
           store = storage.NewRedisStorage(cfg.RedisURL, cfg.BlockDuration)
       } else {
           store = storage.NewMemoryStorage(cfg.BlockDuration)
       }
       
       // Create defender
       d := defender.NewDefender(defender.DefenderOptions{
           AnalysisThreshold:    cfg.AnalysisThreshold,
           BlockDuration:        cfg.BlockDuration,
           Storage:              store,
           MaxTrackedIPs:        cfg.MaxTrackedIPs,
           EvictionBatchPct:     0.10,
           EvictionThresholdPct: 0.93,
           SimulationMode:       cfg.SimulationMode,
       })
       
       // Load extension configuration
       extConfigPath := os.Getenv("EXTENSION_CONFIG")
       if extConfigPath == "" {
           extConfigPath = "/etc/ops-defender/extensions.json"
       }
       
       extCfg, err := extconfig.LoadConfig(extConfigPath)
       if err != nil {
           log.Printf("Warning: Could not load extension config: %v", err)
       } else {
           // Register your private extension
           ipFilter := filters.NewIPFilter(extCfg.AllowedIPs)
           d.RegisterExtension(ipFilter)
           log.Printf("Registered IP filter extension with %d allowed IPs", len(extCfg.AllowedIPs))
       }
       
       // Setup HTTP server (same as core)
       http.HandleFunc("/check", d.CheckRequest)
       http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
           w.WriteHeader(http.StatusOK)
           w.Write([]byte("OK"))
       })
       http.HandleFunc("/stats", d.GetStats)
       http.HandleFunc("/report", d.GetReport)
       
       port := os.Getenv("PORT")
       if port == "" {
           port = "8080"
       }
       
       log.Printf("Starting Ops Defender with custom extensions on port %s...", port)
       if err := http.ListenAndServe(":"+port, nil); err != nil {
           log.Fatalf("Server failed to start: %v", err)
       }
   }
   ```

7. **Extension Configuration File** (`extensions.json`):
   ```json
   {
       "allowed_ips": [
           "10.0.0.1",
           "192.168.1.100",
           "203.0.113.42"
       ]
   }
   ```

8. **Build Process**:
   ```bash
   # In your private repository
   cd ops-defender-extensions
   
   # Build custom binary
   go build -o ops-defender-custom ./cmd/ops-defender-custom
   
   # Or with optimizations
   CGO_ENABLED=0 go build -ldflags="-s -w" -o ops-defender-custom ./cmd/ops-defender-custom
   ```

9. **Deployment**:
   ```bash
   # Copy binary and config to server
   scp ops-defender-custom your-server:/usr/local/bin/
   scp extensions.json your-server:/etc/ops-defender/
   
   # Run with extension config
   export EXTENSION_CONFIG=/etc/ops-defender/extensions.json
   /usr/local/bin/ops-defender-custom
   ```

10. **Docker Deployment** (optional):
    ```dockerfile
    # In ops-defender-extensions repo
    FROM golang:1.25-alpine AS builder
    WORKDIR /build
    
    # Copy dependencies
    COPY go.mod go.sum ./
    RUN go mod download
    
    # Copy source
    COPY . .
    
    # Build
    RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o ops-defender-custom ./cmd/ops-defender-custom
    
    # Runtime image
    FROM alpine:latest
    RUN apk --no-cache add ca-certificates
    WORKDIR /app
    
    # Copy binary and config
    COPY --from=builder /build/ops-defender-custom .
    COPY extensions.json /etc/ops-defender/
    
    ENV EXTENSION_CONFIG=/etc/ops-defender/extensions.json
    EXPOSE 8080
    
    CMD ["./ops-defender-custom"]
    ```

**Benefits of Private Repository Approach:**

✓ **IP Protection**: Your business logic stays private  
✓ **Separation of Concerns**: Core system vs. custom extensions  
✓ **Independent Updates**: Update core without touching extensions  
✓ **Access Control**: Only authorized developers access extension repo  
✓ **Custom Versioning**: Pin to specific Ops Defender versions  
✓ **Easier Auditing**: Clear boundary between open-source and proprietary code

**Multi-Root Workspace for Development:**

For local development with both repositories:

```bash
# Clone both repos
git clone https://github.com/luisgizirian/ops-defender.git
git clone https://github.com/your-org/ops-defender-extensions.git

# In VS Code:
# 1. File > Add Folder to Workspace (add ops-defender)
# 2. File > Add Folder to Workspace (add ops-defender-extensions)
# 3. File > Save Workspace As... → ops-defender-dev.code-workspace

# Reopen in devcontainer (uses ops-defender's devcontainer)
# Both repos accessible, can import types across repos
```

Example structure:
```
workspace/
├── ops-defender/                  # Core repository (public)
│   ├── .devcontainer/            # Dev container config
│   ├── internal/
│   │   └── extensions/           # Extension interfaces
│   └── ...
└── ops-defender-extensions/       # Your private repo
    ├── filters/                   # Your custom extensions
    ├── config/                    # Your config loading
    └── cmd/
        └── ops-defender-custom/   # Custom build
```

**Testing Your Extension:**

```bash
# Unit test your extension independently
cd ops-defender-extensions
go test ./filters/...

# Integration test with core
go test -v ./cmd/ops-defender-custom/...

# Load test with your extension enabled
cd ../ops-defender
DURATION=60 RPS=20 ./scripts/load-test.sh
```

**Security Best Practices:**

- Store sensitive IPs/rules in encrypted config files
- Use environment variables for secrets (API keys, etc.)
- Implement proper access control on extension config files
- Audit log all bypass decisions
- Regularly review extension logic for security issues
- Pin Ops Defender version in go.mod for stability

Build:
```bash
# Build with extensions from separate module
cd workspace
go mod edit -replace github.com/ops/defender=./ops-defender
go build -o ops-defender-custom ./cmd/main.go
```
