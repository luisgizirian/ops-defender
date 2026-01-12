# Extension Examples

This directory contains examples of how to extend Ops Defender using the extensibility framework.

## Overview

Ops Defender provides a clean extensibility model that allows you to add custom functionality without modifying the core codebase. This enables:

- **Private extensions** in separate repositories
- **No forking** or rebasing required
- **Composition over modification**
- **Stable extension contracts**

## Example Extensions

### 1. Pattern Provider (`ExamplePatternProvider`)

Demonstrates how to add custom suspicious pattern detection:

```go
type ExamplePatternProvider struct{}

func (e *ExamplePatternProvider) GetPatterns() []string {
    return []string{
        `/internal-api`,     // Block access to internal APIs
        `/company-admin`,    // Company-specific admin paths
        `\.backup$`,         // Backup file attempts
        // ... more patterns
    }
}
```

**Use cases:**
- Add organization-specific attack patterns
- Block access to internal/private endpoints
- Detect company-specific threats

### 2. Critical Pattern Provider (`CriticalPatternProvider`)

Shows how to use priority to ensure critical patterns are checked first:

```go
func (c *CriticalPatternProvider) GetPriority() int {
    return 100 // High priority - checked first
}
```

**Use cases:**
- Authentication bypass detection
- Critical security vulnerabilities
- Zero-day exploit patterns

### 3. Whitelist Provider (`ExampleWhitelistProvider`)

Demonstrates how to whitelist organization-specific paths:

```go
func (e *ExampleWhitelistProvider) GetWhitelistPatterns() []string {
    return []string{
        `^/public/.*\.(js|css|png|jpg|svg)$`,  // Public assets
        `^/api/v1/health$`,                     // Health checks
        // ... more whitelisted paths
    }
}
```

**Use cases:**
- Whitelist CDN content
- Exclude health check endpoints
- Allow public API paths

### 4. Blocking Rule Provider (`ExampleBlockingRuleProvider`)

Shows how to implement custom blocking logic based on request patterns:

```go
func (e *ExampleBlockingRuleProvider) ShouldBlock(ip string, requestCount int, requestLogs []extensions.RequestLogInfo) (bool, string) {
    // Custom logic to determine if IP should be blocked
    if requestCount > 50 {
        return true, "excessive request rate"
    }
    return false, ""
}
```

**Use cases:**
- Rate limiting logic
- Behavioral analysis
- Custom threat detection
- Organization-specific rules

### 5. Test Rule Provider (`ExampleTestRuleProvider`)

Demonstrates how to extend unit tests with custom test cases:

```go
func (e *ExampleTestRuleProvider) GetTestCases() []extensions.TestCase {
    return []extensions.TestCase{
        {
            Name:       "Should block internal API access",
            URI:        "/internal-api/users",
            ShouldFail: true,
            Pattern:    "/internal-api",
        },
        // ... more test cases
    }
}
```

**Use cases:**
- Test custom patterns
- Validate organization-specific rules
- Continuous integration testing

## Usage

These examples are reference implementations. In practice, you would:

1. **Create a private repository** for your extensions
2. **Import the extension-points package** from the public Ops Defender repo
3. **Implement the interfaces** for your specific needs
4. **Register your extensions** when initializing the Defender

See the main [EXTENSIBILITY.md](../../EXTENSIBILITY.md) document for complete integration instructions.

## File Structure

```
examples/extensions/
├── README.md                  # This file
└── example_providers.go       # Example extension implementations
```

## Best Practices

1. **Keep extensions focused**: Each provider should have a single responsibility
2. **Use appropriate priorities**: Critical patterns should have higher priority
3. **Document patterns**: Add comments explaining why each pattern exists
4. **Test thoroughly**: Use TestRuleProvider to validate your patterns
5. **Monitor performance**: Complex regex patterns can impact performance

## Next Steps

- Read [EXTENSIBILITY.md](../../EXTENSIBILITY.md) for the complete architecture guide
- See [extension-points/interfaces.go](../../extension-points/interfaces.go) for interface definitions
- Check the integration examples for how to register extensions
