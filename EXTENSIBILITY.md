# Ops Defender Extensibility Architecture

> **🤖 EXPERIMENTAL NOTICE:**  
> This extensibility framework is part of an experimental project. While it demonstrates modern extension patterns and includes comprehensive examples, thoroughly test any extensions in staging before production use.

## Overview

Ops Defender uses an **Open Core + Private Extension** architecture that allows organizations to add custom functionality without forking or modifying the core codebase. This approach provides:

- ✅ **No forking required** - Extensions live in separate repositories
- ✅ **No rebasing needed** - Core updates don't conflict with extensions
- ✅ **Stable contracts** - Well-defined interfaces that rarely change
- ✅ **Clean separation** - Public core remains generic, extensions add specifics
- ✅ **Composition over modification** - Extend behavior through interfaces, not code changes

## Architecture

### High-Level Structure

```
┌──────────────────────────────┐
│    Public Open Core          │
│    (github.com/luisgizirian/ops-defender) │
│                              │
│  ┌────────────────────────┐ │
│  │   Core Defense Logic   │ │
│  │   - Pattern matching   │ │
│  │   - IP tracking        │ │
│  │   - Request analysis   │ │
│  └────────────────────────┘ │
│           ▲                  │
│           │                  │
│  ┌────────────────────────┐ │
│  │  Extension Contracts   │ │◄─────┐
│  │  (extension-points/)   │ │      │
│  │  - PatternProvider     │ │      │
│  │  - BlockingRuleProvider│ │      │
│  │  - WhitelistProvider   │ │      │
│  │  - TestRuleProvider    │ │      │
│  │  - PreRequestHandler   │ │      │
│  │  - PostRequestHandler  │ │      │
│  └────────────────────────┘ │      │
│           ▲                  │      │
└───────────┼──────────────────┘      │
            │                         │
            │ implements              │
            │                         │
┌───────────▼──────────────────┐      │
│  Private Extensions          │──────┘
│  (your-company/extensions)   │
│                              │
│  - Custom attack patterns    │
│  - Org-specific blocking     │
│  - Internal whitelists       │
│  - Custom test cases         │
└──────────────────────────────┘
```

### Repository Structure

**Public Repository** (github.com/luisgizirian/ops-defender):
```
ops-defender/
├── extension-points/          # Extension interfaces (stable contracts)
│   └── interfaces.go          # PatternProvider, BlockingRuleProvider, etc.
├── internal/
│   └── defender/              # Core defense logic
│       └── defender.go        # Uses ExtensionRegistry
├── examples/
│   └── extensions/            # Reference implementations
│       ├── README.md
│       └── example_providers.go
└── EXTENSIBILITY.md           # This document
```

**Private Repository** (your-company/ops-defender-extensions):
```
ops-defender-extensions/
├── go.mod                     # Depends on public core
├── patterns/
│   ├── internal_api.go        # Company-specific patterns
│   └── critical_paths.go      # High-priority patterns
├── rules/
│   └── rate_limiting.go       # Custom blocking rules
├── whitelists/
│   └── cdn_paths.go           # Whitelisted endpoints
└── main.go                    # Registers extensions with core
```

## Extension Points

### 1. PatternProvider Interface

Add custom suspicious patterns without modifying core code.

**Interface:**
```go
type PatternProvider interface {
    GetPatterns() []string    // Return regex patterns
    GetName() string          // Provider name for logging
    GetPriority() int         // Higher = evaluated first
}
```

**Example:**
```go
type CompanyPatternProvider struct{}

func (c *CompanyPatternProvider) GetPatterns() []string {
    return []string{
        `/internal-api`,       // Block internal API access
        `/company-admin`,      // Company-specific admin
        `\.backup$`,           // Backup file attempts
    }
}

func (c *CompanyPatternProvider) GetName() string {
    return "Company Internal Patterns"
}

func (c *CompanyPatternProvider) GetPriority() int {
    return 50  // Medium-high priority
}
```

**Use Cases:**
- Organization-specific attack patterns
- Internal endpoint protection
- Industry-specific threat detection
- Compliance requirements

### 2. BlockingRuleProvider Interface

Implement custom logic to determine if an IP should be blocked.

**Interface:**
```go
type BlockingRuleProvider interface {
    ShouldBlock(ip string, requestCount int, requestLogs []RequestLogInfo) (bool, string)
    GetName() string
    GetPriority() int
}
```

**Example:**
```go
type RateLimitingRule struct{}

func (r *RateLimitingRule) ShouldBlock(ip string, requestCount int, requestLogs []RequestLogInfo) (bool, string) {
    // Block if more than 100 requests in short time
    if requestCount > 100 {
        return true, "rate limit exceeded"
    }
    
    // Block if multiple admin access attempts
    adminAttempts := 0
    for _, log := range requestLogs {
        if strings.Contains(log.URI, "admin") {
            adminAttempts++
        }
    }
    
    if adminAttempts >= 5 {
        return true, "multiple admin access attempts"
    }
    
    return false, ""
}

func (r *RateLimitingRule) GetName() string {
    return "Custom Rate Limiting"
}

func (r *RateLimitingRule) GetPriority() int {
    return 0  // Normal priority
}
```

**Use Cases:**
- Custom rate limiting
- Behavioral analysis
- Geo-blocking
- Time-based restrictions
- User agent filtering

### 3. WhitelistProvider Interface

Add organization-specific paths that should never be blocked.

**Interface:**
```go
type WhitelistProvider interface {
    GetWhitelistPatterns() []string
    GetName() string
    GetPriority() int
}
```

**Example:**
```go
type CDNWhitelistProvider struct{}

func (c *CDNWhitelistProvider) GetWhitelistPatterns() []string {
    return []string{
        `^/cdn/.*`,                          // CDN content
        `^/public/.*\.(js|css|png|jpg)$`,    // Public assets
        `^/api/v1/health$`,                  // Health checks
        `^/.well-known/security\.txt$`,      // Security disclosure
    }
}

func (c *CDNWhitelistProvider) GetName() string {
    return "CDN Whitelist"
}

func (c *CDNWhitelistProvider) GetPriority() int {
    return 100  // High priority - checked first
}
```

**Use Cases:**
- Whitelist CDN paths
- Exclude monitoring endpoints
- Allow public API access
- SEO-related files

### 4. TestRuleProvider Interface

Extend unit tests with custom test cases for your patterns.

**Interface:**
```go
type TestRuleProvider interface {
    GetTestCases() []TestCase
    GetName() string
}

type TestCase struct {
    Name       string  // Test description
    URI        string  // URI to test
    ShouldFail bool    // Should be detected as suspicious
    Pattern    string  // Pattern being tested
}
```

**Example:**
```go
type CompanyTestProvider struct{}

func (c *CompanyTestProvider) GetTestCases() []TestCase {
    return []TestCase{
        {
            Name:       "Should block internal API",
            URI:        "/internal-api/users",
            ShouldFail: true,
            Pattern:    "/internal-api",
        },
        {
            Name:       "Should allow public API",
            URI:        "/api/v1/public/data",
            ShouldFail: false,
        },
    }
}

func (c *CompanyTestProvider) GetName() string {
    return "Company Test Cases"
}
```

**Use Cases:**
- Validate custom patterns
- Regression testing
- CI/CD integration
- Documentation through tests

### 5. PreRequestHandler Interface

Hook into the request lifecycle **before** any core processing (logging, caching, analysis).

**Interface:**
```go
type PreRequestHandler interface {
    Handle(ip, uri, userAgent string) RequestAction
    GetName() string
    GetPriority() int
}

type RequestAction int
const (
    Continue  RequestAction = iota  // Proceed with normal processing
    Terminate                        // End processing, send 200 OK
)
```

**Example:**
```go
type TrustedIPHandler struct {
    trustedCIDRs []*net.IPNet
}

func (t *TrustedIPHandler) Handle(ip, uri, userAgent string) extensions.RequestAction {
    parsedIP := net.ParseIP(ip)
    for _, cidr := range t.trustedCIDRs {
        if cidr.Contains(parsedIP) {
            // Bypass all processing for trusted IPs
            return extensions.Terminate
        }
    }
    // Continue normal processing
    return extensions.Continue
}

func (t *TrustedIPHandler) GetName() string {
    return "Trusted IP Bypass"
}

func (t *TrustedIPHandler) GetPriority() int {
    return 100  // High priority - checked first
}
```

**Use Cases:**
- IP exclusion/whitelisting
- Early request filtering
- Custom authentication checks
- Performance optimizations (skip processing for known-good traffic)

**Performance:** Pre-handlers add ~50-100ns per handler when extensions are registered. Zero overhead when `extensionRegistry` is nil.

### 6. PostRequestHandler Interface

Hook into the request lifecycle **after** core processing (logging) but **before** final response.

**Interface:**
```go
type PostRequestHandler interface {
    Handle(ip, uri, userAgent string, requestCount int) RequestAction
    GetName() string
    GetPriority() int
}
```

**Example (Request Timing):**
```go
type RequestTimingHandler struct {
    extension *RequestTimingExtension  // Shared state with pre-handler
}

func (r *RequestTimingHandler) Handle(ip, uri, userAgent string, requestCount int) extensions.RequestAction {
    // Access timing data captured by pre-handler
    duration := r.extension.GetDuration(ip, uri)
    log.Printf("[TIMING] IP=%s, Duration=%v, Count=%d", ip, duration, requestCount)
    
    // Continue with normal response
    return extensions.Continue
}
```

**Use Cases:**
- Request timing/profiling
- Custom logging
- Audit trails
- Post-processing metrics
- Response manipulation (future enhancement)

**Performance:** Post-handlers add ~50-100ns per handler. Executed after logging, so no impact on critical path.

### Combining Pre + Post Handlers

Pre and post handlers can work together by sharing state:

```go
// See examples/extensions/example_providers.go for complete implementation
type RequestTimingExtension struct {
    mu         sync.RWMutex
    startTimes map[string]time.Time
}

// Pre-handler captures start time
func (r *RequestTimingExtension) Handle(ip, uri, userAgent string) extensions.RequestAction {
    r.startTimes[ip+":"+uri] = time.Now()
    return extensions.Continue
}

// Post-handler logs duration
func (p *PostRequestTimingHandler) Handle(ip, uri, userAgent string, requestCount int) extensions.RequestAction {
    startTime := p.extension.startTimes[ip+":"+uri]
    duration := time.Since(startTime)
    log.Printf("[TIMING] Duration=%v", duration)
    return extensions.Continue
}
```

See [examples/extensions/example_providers.go](examples/extensions/example_providers.go) for a complete working example.

## Integration Guide

> **💡 Development Environment:**  
> For the best development experience with both core and private extensions in a unified devcontainer, see [Multi-Repo Devcontainer Guide](examples/extensions/MULTI-REPO-DEVCONTAINER.md).

### Step 1: Create Private Extension Repository

```bash
# Create new Go module for your extensions
mkdir ops-defender-extensions
cd ops-defender-extensions
go mod init your-company/ops-defender-extensions

# Add dependency on public core
go get github.com/luisgizirian/ops-defender
```

### Step 2: Implement Extension Interfaces

Create your extension providers:

```go
// patterns/internal_api.go
package patterns

import "github.com/luisgizirian/ops-defender/extension-points"

type InternalAPIPatternProvider struct{}

func (i *InternalAPIPatternProvider) GetPatterns() []string {
    return []string{
        `/internal-api`,
        `/company-admin`,
        // ... your patterns
    }
}

func (i *InternalAPIPatternProvider) GetName() string {
    return "Internal API Patterns"
}

func (i *InternalAPIPatternProvider) GetPriority() int {
    return 50
}
```

### Step 3: Register Extensions

In your private repository's main.go:

```go
package main

import (
    "github.com/luisgizirian/ops-defender/extension-points"
    "github.com/luisgizirian/ops-defender/internal/defender"
    "your-company/ops-defender-extensions/patterns"
    "your-company/ops-defender-extensions/rules"
)

func main() {
    // Create extension registry
    registry := extensions.NewExtensionRegistry()
    
    // Register your extensions
    registry.RegisterPatternProvider(&patterns.InternalAPIPatternProvider{})
    registry.RegisterPatternProvider(&patterns.CriticalPatternProvider{})
    registry.RegisterBlockingRuleProvider(&rules.RateLimitingRule{})
    registry.RegisterWhitelistProvider(&patterns.CDNWhitelistProvider{})
    
    // Create defender with extensions
    d := defender.NewDefenderWithExtensions(
        defender.DefenderOptions{
            AnalysisThreshold: 5,
            BlockDuration:     60 * time.Minute,
            Storage:           storage,
            MaxTrackedIPs:     10000,
        },
        registry,
    )
    
    // Continue with normal setup...
}
```

### Step 4: Build and Deploy

```bash
# Build your extended version
go build -o ops-defender-extended

# Deploy as you would the standard version
./ops-defender-extended
```

## Extension Best Practices

### 1. Keep Extensions Focused

Each provider should have a single, clear purpose:

✅ **Good:**
```go
type RateLimitingRule struct{}  // Single responsibility
type GeoBlockingRule struct{}   // Single responsibility
```

❌ **Bad:**
```go
type AllSecurityRules struct{}  // Too many responsibilities
```

### 2. Use Priorities Wisely

- **0-49**: Normal priority (most extensions)
- **50-99**: Medium-high priority (important patterns)
- **100+**: Critical priority (security-critical patterns)

### 3. Test Thoroughly

Always implement TestRuleProvider for your patterns:

```go
func (t *MyTestProvider) GetTestCases() []TestCase {
    return []TestCase{
        // Test positive cases (should block)
        {Name: "Block attack", URI: "/attack", ShouldFail: true},
        // Test negative cases (should allow)
        {Name: "Allow valid", URI: "/valid", ShouldFail: false},
    }
}
```

### 4. Document Patterns

Add comments explaining why each pattern exists:

```go
func (p *MyProvider) GetPatterns() []string {
    return []string{
        `/internal-api`,  // Block: Internal API discovered in 2024 breach attempt
        `/debug`,         // Block: Debug endpoint exposed in staging incident
    }
}
```

### 5. Monitor Performance

Complex regex patterns can impact performance:

```go
// ✅ Good: Simple, fast pattern
`/admin`

// ⚠️ Careful: Complex pattern, test performance
`/api/v\d+/users/\d+/posts/\d+/comments`

// ❌ Avoid: Catastrophic backtracking possible
`(a+)+b`
```

### 6. Version Extensions

Use semantic versioning for your private extensions:

```go
// go.mod
module your-company/ops-defender-extensions

go 1.25

require (
    github.com/luisgizirian/ops-defender v1.2.3  // Pin to specific version
)
```

## Testing Extensions

### Unit Testing

Test your extensions independently:

```go
func TestInternalAPIPattern(t *testing.T) {
    provider := &InternalAPIPatternProvider{}
    patterns := provider.GetPatterns()
    
    if len(patterns) == 0 {
        t.Error("Expected patterns, got none")
    }
}
```

### Integration Testing

Test with the full Defender:

```go
func TestExtensionsIntegration(t *testing.T) {
    registry := extensions.NewExtensionRegistry()
    registry.RegisterPatternProvider(&patterns.InternalAPIPatternProvider{})
    
    // Test that patterns are loaded
    allPatterns := registry.GetAllPatterns()
    if len(allPatterns) == 0 {
        t.Error("Extensions not loaded")
    }
}
```

### End-to-End Testing

Test the complete flow:

```bash
# Start defender with extensions
./ops-defender-extended

# Test blocking
curl -H "X-Real-IP: 192.168.1.1" \
     -H "X-Original-URI: /internal-api/users" \
     http://localhost:8080/check

# Should return 403 after analysis threshold
```

## Migration Guide

### Migrating from Forked Core

If you currently have a forked version of Ops Defender:

1. **Extract your custom patterns** into a PatternProvider
2. **Move blocking logic** into a BlockingRuleProvider
3. **Create whitelist provider** for your whitelisted paths
4. **Set up private repository** for your extensions
5. **Test thoroughly** before switching
6. **Update deployment** to use extended version

**Before (forked):**
```go
// Modified defender.go in forked repo
patterns := []string{
    // ... original patterns ...
    `/your-custom-pattern`,  // Your addition
}
```

**After (extended):**
```go
// your-company/extensions/patterns.go
type YourPatternProvider struct{}

func (y *YourPatternProvider) GetPatterns() []string {
    return []string{
        `/your-custom-pattern`,
    }
}
```

## Troubleshooting

### Extensions Not Loading

**Problem:** Extensions registered but not working

**Check:**
1. Extensions properly registered in main.go
2. Priority settings (higher = checked first)
3. Regex patterns compile without errors
4. Go module dependencies resolved

### Performance Issues

**Problem:** Request processing slow after adding extensions

**Solutions:**
1. Simplify complex regex patterns
2. Use higher priorities for frequently matched patterns
3. Profile with `go test -bench` to find slow patterns
4. Consider caching compiled patterns

### Pattern Conflicts

**Problem:** Patterns interfere with each other

**Solutions:**
1. Use priorities to control evaluation order
2. Make patterns more specific
3. Use negative lookaheads in regex when needed
4. Test combinations thoroughly

## Examples

See the [examples/extensions/](examples/extensions/) directory for:

- Complete working examples of all extension types
- Best practices demonstrations
- Integration patterns
- Testing approaches

## API Stability

### Stable (Won't Change)

- Extension interface definitions
- ExtensionRegistry core methods
- Priority system
- Registration patterns

### May Evolve

- RequestLogInfo structure (may add fields)
- Helper utilities
- Internal implementation details

### Breaking Changes

Breaking changes to extension interfaces will:
- Be announced in release notes
- Include migration guide
- Provide deprecation period
- Bump major version

## Support

- **Documentation:** See examples in `examples/extensions/`
- **Issues:** File in public repo with `extension` label
- **Discussions:** Use GitHub Discussions for questions
- **Security:** Email security issues privately

## Summary

The Ops Defender extensibility architecture enables:

1. ✅ **Private customization** without forking
2. ✅ **Stable upgrade path** from public core
3. ✅ **Clean separation** between generic and specific
4. ✅ **Flexible extension points** for all major features:
   - Pattern detection (PatternProvider)
   - Custom blocking rules (BlockingRuleProvider)
   - URI whitelisting (WhitelistProvider)
   - Early request hooks (PreRequestHandler)
   - Late request hooks (PostRequestHandler)
   - Test case extensions (TestRuleProvider)
5. ✅ **Production-ready patterns** with examples and tests
6. ✅ **Zero overhead** when extensions not registered

Start with the examples, implement your extensions in a private repository, and enjoy the benefits of Open Core + Private Extension architecture!
