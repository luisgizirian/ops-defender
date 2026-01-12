package examples

import (
	"github.com/ops/defender/extension-points"
)

// ExamplePatternProvider demonstrates how to add custom attack patterns
// This would typically be in a private repository, not the public core
type ExamplePatternProvider struct{}

func (e *ExamplePatternProvider) GetPatterns() []string {
	return []string{
		`/internal-api`,          // Block access to internal APIs
		`/company-admin`,         // Company-specific admin paths
		`\.backup$`,              // Backup file attempts
		`\.bak$`,                 // Backup file attempts
		`/debug`,                 // Debug endpoints
		`/console`,               // Console access attempts
		`\.sql$`,                 // SQL file access
		`\.db$`,                  // Database file access
		`/actuator`,              // Spring Boot actuator endpoints
		`/swagger`,               // API documentation endpoints
		`\.yaml$`,                // Configuration files
		`\.yml$`,                 // Configuration files
		`\.json$.*password`,      // JSON files with passwords
		`/graphql.*mutation.*delete`, // Dangerous GraphQL mutations
	}
}

func (e *ExamplePatternProvider) GetName() string {
	return "Example Custom Patterns"
}

func (e *ExamplePatternProvider) GetPriority() int {
	return 0 // Normal priority
}

// CriticalPatternProvider demonstrates high-priority patterns
type CriticalPatternProvider struct{}

func (c *CriticalPatternProvider) GetPatterns() []string {
	return []string{
		`/auth/bypass`,           // Authentication bypass attempts
		`/__debug__`,             // Django debug endpoints
		`/\.well-known/.*admin`,  // Admin discovery
		`cmd=.*exec`,             // Command execution attempts
		`system\(`,               // System command injection
	}
}

func (c *CriticalPatternProvider) GetName() string {
	return "Critical Security Patterns"
}

func (c *CriticalPatternProvider) GetPriority() int {
	return 100 // High priority - checked first
}

// ExampleWhitelistProvider demonstrates how to whitelist organization-specific paths
type ExampleWhitelistProvider struct{}

func (e *ExampleWhitelistProvider) GetWhitelistPatterns() []string {
	return []string{
		`^/public/.*\.(js|css|png|jpg|svg)$`,       // Public assets
		`^/cdn/.*`,                                  // CDN content
		`^/static/vendor/.*`,                        // Third-party libraries
		`^/api/v1/health$`,                          // Health check endpoints
		`^/api/v1/metrics$`,                         // Metrics endpoints
		`^/.well-known/security\.txt$`,              // Security disclosure
		`^/robots\.txt$`,                            // SEO files
		`^/sitemap\.xml$`,                           // SEO files
	}
}

func (e *ExampleWhitelistProvider) GetName() string {
	return "Example Whitelist Rules"
}

func (e *ExampleWhitelistProvider) GetPriority() int {
	return 0
}

// ExampleBlockingRuleProvider demonstrates custom blocking logic
type ExampleBlockingRuleProvider struct{}

func (e *ExampleBlockingRuleProvider) ShouldBlock(ip string, requestCount int, requestLogs []extensions.RequestLogInfo) (bool, string) {
	// Example 1: Block IPs that make too many requests in a short time
	if requestCount > 50 {
		return true, "excessive request rate"
	}
	
	// Example 2: Block IPs that access multiple admin paths
	adminPaths := 0
	for _, log := range requestLogs {
		if containsString(log.URI, "admin") || containsString(log.URI, "wp-admin") {
			adminPaths++
		}
	}
	
	if adminPaths >= 3 {
		return true, "multiple admin path access attempts"
	}
	
	// Example 3: Block IPs with suspicious user agents
	botCount := 0
	for _, log := range requestLogs {
		if containsString(log.UserAgent, "bot") || 
		   containsString(log.UserAgent, "crawler") ||
		   containsString(log.UserAgent, "scanner") {
			botCount++
		}
	}
	
	if botCount >= 2 {
		return true, "suspicious user agent pattern"
	}
	
	return false, ""
}

func (e *ExampleBlockingRuleProvider) GetName() string {
	return "Example Custom Blocking Rules"
}

func (e *ExampleBlockingRuleProvider) GetPriority() int {
	return 0
}

// Helper function for case-insensitive string matching
func containsString(s, substr string) bool {
	sLower := toLower(s)
	substrLower := toLower(substr)
	return contains(sLower, substrLower)
}

func toLower(s string) string {
	result := make([]rune, len(s))
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			result[i] = r + 32
		} else {
			result[i] = r
		}
	}
	return string(result)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && indexOfSubstring(s, substr) >= 0
}

func indexOfSubstring(s, substr string) int {
	if len(substr) == 0 {
		return 0
	}
	if len(s) < len(substr) {
		return -1
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// ExampleTestRuleProvider demonstrates how to add custom test cases
type ExampleTestRuleProvider struct{}

func (e *ExampleTestRuleProvider) GetTestCases() []extensions.TestCase {
	return []extensions.TestCase{
		{
			Name:       "Should block internal API access",
			URI:        "/internal-api/users",
			ShouldFail: true,
			Pattern:    "/internal-api",
		},
		{
			Name:       "Should block company admin",
			URI:        "/company-admin/settings",
			ShouldFail: true,
			Pattern:    "/company-admin",
		},
		{
			Name:       "Should allow public API",
			URI:        "/api/v1/public/data",
			ShouldFail: false,
			Pattern:    "",
		},
		{
			Name:       "Should block backup file access",
			URI:        "/database.backup",
			ShouldFail: true,
			Pattern:    "\\.backup$",
		},
		{
			Name:       "Should block debug endpoint",
			URI:        "/debug/vars",
			ShouldFail: true,
			Pattern:    "/debug",
		},
		{
			Name:       "Should block actuator endpoints",
			URI:        "/actuator/env",
			ShouldFail: true,
			Pattern:    "/actuator",
		},
	}
}

func (e *ExampleTestRuleProvider) GetName() string {
	return "Example Custom Test Cases"
}
