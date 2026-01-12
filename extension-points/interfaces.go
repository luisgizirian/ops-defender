package extensions

import (
	"regexp"
)

// PatternProvider defines the interface for extending suspicious pattern detection
// Private extensions can implement this to add custom attack patterns without modifying core code
type PatternProvider interface {
	// GetPatterns returns a list of regex patterns to detect suspicious requests
	// Patterns should be case-insensitive and follow Go regexp syntax
	GetPatterns() []string

	// GetName returns a descriptive name for this pattern provider
	// Used for logging and debugging
	GetName() string

	// GetPriority returns the priority of this provider (higher = evaluated first)
	// Use 0 for normal priority, higher values for critical patterns
	GetPriority() int
}

// BlockingRuleProvider defines the interface for custom IP blocking rules
// Private extensions can implement this to add organization-specific blocking logic
type BlockingRuleProvider interface {
	// ShouldBlock evaluates whether a given IP should be blocked
	// Returns true if the IP should be blocked, along with a reason string
	ShouldBlock(ip string, requestCount int, requestLogs []RequestLogInfo) (bool, string)

	// GetName returns a descriptive name for this blocking rule provider
	GetName() string

	// GetPriority returns the priority of this rule (higher = evaluated first)
	GetPriority() int
}

// RequestLogInfo provides read-only access to request log information
// Used by BlockingRuleProvider to analyze request patterns
type RequestLogInfo struct {
	URI           string
	Timestamp     string
	UserAgent     string
	IsWhitelisted bool
}

// TestRuleProvider defines the interface for extending unit tests
// Private extensions can implement this to add custom test cases
type TestRuleProvider interface {
	// GetTestCases returns a list of test cases for pattern detection
	GetTestCases() []TestCase

	// GetName returns a descriptive name for this test provider
	GetName() string
}

// TestCase represents a single test case for pattern detection
type TestCase struct {
	Name       string // Descriptive name of the test case
	URI        string // URI to test
	ShouldFail bool   // Whether this URI should be detected as suspicious
	Pattern    string // Optional: specific pattern being tested
}

// WhitelistProvider defines the interface for custom whitelisting rules
// Private extensions can implement this to add organization-specific whitelist patterns
type WhitelistProvider interface {
	// GetWhitelistPatterns returns regex patterns for URIs that should never be blocked
	GetWhitelistPatterns() []string

	// GetName returns a descriptive name for this whitelist provider
	GetName() string

	// GetPriority returns the priority of this provider (higher = evaluated first)
	GetPriority() int
}

// ExtensionRegistry manages all registered extensions
// This is the central point for registering and accessing extensions
type ExtensionRegistry struct {
	patternProviders       []PatternProvider
	blockingRuleProviders  []BlockingRuleProvider
	testRuleProviders      []TestRuleProvider
	whitelistProviders     []WhitelistProvider
}

// NewExtensionRegistry creates a new extension registry
func NewExtensionRegistry() *ExtensionRegistry {
	return &ExtensionRegistry{
		patternProviders:       make([]PatternProvider, 0),
		blockingRuleProviders:  make([]BlockingRuleProvider, 0),
		testRuleProviders:      make([]TestRuleProvider, 0),
		whitelistProviders:     make([]WhitelistProvider, 0),
	}
}

// RegisterPatternProvider registers a new pattern provider
func (r *ExtensionRegistry) RegisterPatternProvider(provider PatternProvider) {
	r.patternProviders = append(r.patternProviders, provider)
}

// RegisterBlockingRuleProvider registers a new blocking rule provider
func (r *ExtensionRegistry) RegisterBlockingRuleProvider(provider BlockingRuleProvider) {
	r.blockingRuleProviders = append(r.blockingRuleProviders, provider)
}

// RegisterTestRuleProvider registers a new test rule provider
func (r *ExtensionRegistry) RegisterTestRuleProvider(provider TestRuleProvider) {
	r.testRuleProviders = append(r.testRuleProviders, provider)
}

// RegisterWhitelistProvider registers a new whitelist provider
func (r *ExtensionRegistry) RegisterWhitelistProvider(provider WhitelistProvider) {
	r.whitelistProviders = append(r.whitelistProviders, provider)
}

// GetAllPatterns returns all patterns from all registered providers, sorted by priority
func (r *ExtensionRegistry) GetAllPatterns() []*regexp.Regexp {
	patterns := make([]*regexp.Regexp, 0)
	
	// Sort providers by priority (highest first)
	sortedProviders := make([]PatternProvider, len(r.patternProviders))
	copy(sortedProviders, r.patternProviders)
	
	for i := 0; i < len(sortedProviders); i++ {
		for j := i + 1; j < len(sortedProviders); j++ {
			if sortedProviders[j].GetPriority() > sortedProviders[i].GetPriority() {
				sortedProviders[i], sortedProviders[j] = sortedProviders[j], sortedProviders[i]
			}
		}
	}
	
	// Compile patterns from all providers
	for _, provider := range sortedProviders {
		for _, pattern := range provider.GetPatterns() {
			if re, err := regexp.Compile(`(?i)` + pattern); err == nil {
				patterns = append(patterns, re)
			}
		}
	}
	
	return patterns
}

// GetAllBlockingRules returns all blocking rule providers, sorted by priority
func (r *ExtensionRegistry) GetAllBlockingRules() []BlockingRuleProvider {
	// Sort by priority (highest first)
	sorted := make([]BlockingRuleProvider, len(r.blockingRuleProviders))
	copy(sorted, r.blockingRuleProviders)
	
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].GetPriority() > sorted[i].GetPriority() {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	
	return sorted
}

// GetAllTestCases returns all test cases from all registered providers
func (r *ExtensionRegistry) GetAllTestCases() []TestCase {
	testCases := make([]TestCase, 0)
	
	for _, provider := range r.testRuleProviders {
		testCases = append(testCases, provider.GetTestCases()...)
	}
	
	return testCases
}

// GetAllWhitelistPatterns returns all whitelist patterns from all providers, sorted by priority
func (r *ExtensionRegistry) GetAllWhitelistPatterns() []*regexp.Regexp {
	patterns := make([]*regexp.Regexp, 0)
	
	// Sort providers by priority (highest first)
	sortedProviders := make([]WhitelistProvider, len(r.whitelistProviders))
	copy(sortedProviders, r.whitelistProviders)
	
	for i := 0; i < len(sortedProviders); i++ {
		for j := i + 1; j < len(sortedProviders); j++ {
			if sortedProviders[j].GetPriority() > sortedProviders[i].GetPriority() {
				sortedProviders[i], sortedProviders[j] = sortedProviders[j], sortedProviders[i]
			}
		}
	}
	
	// Compile patterns from all providers
	for _, provider := range sortedProviders {
		for _, pattern := range provider.GetWhitelistPatterns() {
			if re, err := regexp.Compile(`(?i)` + pattern); err == nil {
				patterns = append(patterns, re)
			}
		}
	}
	
	return patterns
}
