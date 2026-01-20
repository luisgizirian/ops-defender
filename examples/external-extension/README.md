# External Extension Example

This example demonstrates how to create an **external extension** for Ops Defender using the **public `pkg/extensions` package**.

## Key Point: Public API

The `github.com/ops/defender/pkg/extensions` package is **public** and can be imported by external Go modules to implement custom extensions.

## Example: IP Allowlist Extension

Create a new Go module for your extension:

```bash
# Create new directory for your extension
mkdir my-ops-defender-extension
cd my-ops-defender-extension

# Initialize Go module
go mod init github.com/your-org/ops-defender-allowlist

# Create extension file
cat > allowlist.go << 'EOF'
package allowlist

import "github.com/ops/defender/pkg/extensions"

// AllowlistExtension bypasses defense checks for trusted IPs
type AllowlistExtension struct {
    trustedIPs map[string]bool
}

// NewAllowlistExtension creates a new allowlist extension
func NewAllowlistExtension(ips []string) *AllowlistExtension {
    trusted := make(map[string]bool)
    for _, ip := range ips {
        trusted[ip] = true
    }
    return &AllowlistExtension{trustedIPs: trusted}
}

// Name returns the extension identifier
func (e *AllowlistExtension) Name() string {
    return "ip-allowlist"
}

// PreHandleRequest checks if IP is on allowlist
func (e *AllowlistExtension) PreHandleRequest(req extensions.RequestInfo) (extensions.PreHandlerResult, error) {
    if e.trustedIPs[req.IP] {
        return extensions.PreHandlerResult{
            ShouldBypass: true,
            Reason:       "trusted IP on allowlist",
        }, nil
    }
    
    return extensions.PreHandlerResult{ShouldBypass: false}, nil
}
EOF

# Download dependencies
go mod tidy
```

## Using Your Extension

In your Ops Defender deployment, import and register your extension:

```go
package main

import (
    "github.com/ops/defender/internal/defender"
    "github.com/your-org/ops-defender-allowlist"
)

func main() {
    // Create defender instance
    d := defender.NewDefender(defender.DefenderOptions{
        // ... your config
    })
    
    // Register your external extension
    ext := allowlist.NewAllowlistExtension([]string{
        "10.0.0.1",      // Office IP
        "192.168.1.1",   // Internal service
    })
    d.RegisterExtension(ext)
    
    // Start server
    // ...
}
```

## Benefits of External Extensions

✅ **No core modifications** - Extensions live in separate repositories  
✅ **Independent versioning** - Update extensions without rebuilding Ops Defender  
✅ **Private extensions** - Keep proprietary logic in private repos  
✅ **Easy testing** - Test extension logic independently  
✅ **Composability** - Register multiple extensions from different sources

## Advanced Examples

See the main [EXTENSION-EXAMPLE.md](../EXTENSION-EXAMPLE.md) for more advanced patterns including:
- Request logging extensions
- Geo-blocking extensions  
- Custom rate limiting
- Multi-factor authentication integration

## Public API Reference

### `extensions.RequestInfo`
```go
type RequestInfo struct {
    IP        string              // Client IP address
    URI       string              // Requested URI
    UserAgent string              // User-Agent header
    Headers   map[string][]string // All request headers
    Method    string              // HTTP method
}
```

### `extensions.PreHandlerResult`
```go
type PreHandlerResult struct {
    ShouldBypass bool   // If true, skip all Ops Defender processing
    Reason       string // Optional reason for logging
}
```

### `extensions.RequestPreHandler` (Interface)
```go
type RequestPreHandler interface {
    PreHandleRequest(request RequestInfo) (PreHandlerResult, error)
    Name() string
}
```

## Next Steps

1. **Browse examples** in `pkg/extensions/extensions_test.go`
2. **Read extension guide** in [README.md](../../README.md#extension-system)
3. **Check developer docs** in `.github/copilot-instructions.md`
