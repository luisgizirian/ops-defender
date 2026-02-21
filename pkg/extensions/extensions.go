package extensions

import (
	"net/http"
	"time"
)

// RequestInfo contains information about an incoming request that can be inspected by extensions
type RequestInfo struct {
	IP        string              // The client IP address
	URI       string              // The requested URI
	UserAgent string              // The User-Agent header
	Headers   map[string][]string // All request headers
	Method    string              // HTTP method (GET, POST, etc.)
}

// PreHandlerResult contains the result of a pre-handler execution
type PreHandlerResult struct {
	ShouldBypass bool   // If true, the request should bypass all processing and logging
	Reason       string // Optional reason for bypassing (for logging purposes)
}

// RequestPreHandler is the interface that extensions must implement to intercept
// incoming requests before they are processed by the core system.
//
// Extensions implementing this interface can inspect request details and decide
// whether a request should be bypassed (not processed or logged by the core system).
//
// This extensibility point is designed to support various use cases without
// requiring modifications to the core system code.
type RequestPreHandler interface {
	// PreHandleRequest is called before the core system processes an incoming request.
	//
	// Parameters:
	//   - request: Information about the incoming HTTP request
	//
	// Returns:
	//   - PreHandlerResult: Contains bypass decision and optional reason
	//   - error: Any error encountered during pre-handling
	//
	// If ShouldBypass is true, the core system will:
	//   1. Skip all pattern analysis and blocking logic
	//   2. Skip request logging
	//   3. Return HTTP 200 (allow) immediately
	//
	// Note: Pre-handlers are invoked in registration order. The first pre-handler
	// that returns ShouldBypass=true will cause the request to bypass all processing.
	PreHandleRequest(request RequestInfo) (PreHandlerResult, error)

	// Name returns a unique identifier for this extension (used for logging and debugging)
	Name() string
}

// RequestInfoFromHTTP creates a RequestInfo from an http.Request
func RequestInfoFromHTTP(r *http.Request, ip, uri string) RequestInfo {
	return RequestInfo{
		IP:        ip,
		URI:       uri,
		UserAgent: r.Header.Get("User-Agent"),
		Headers:   r.Header,
		Method:    r.Method,
	}
}

// PostHandlerContext contains information about the request processing result
// that can be inspected by post-handler extensions.
type PostHandlerContext struct {
	Request      RequestInfo // The original request information
	WasBlocked   bool        // True if the request was blocked by core logic
	BlockReason  string      // Reason for blocking (if WasBlocked is true)
	WasBypassedByPreHandler bool // True if request was bypassed by a pre-handler
}

// PostHandlerResult contains the result of a post-handler execution
type PostHandlerResult struct {
	ShouldOverride bool   // If true, override the core system's decision
	ShouldBlock    bool   // If ShouldOverride is true, whether to block (true) or allow (false)
	Reason         string // Optional reason for overriding (for logging purposes)
}

// RequestPostHandler is the interface that extensions must implement to intercept
// requests after they have been processed by the core system but before the final
// response is sent.
//
// Extensions implementing this interface can inspect the processing result and
// decide whether to override the core system's block/allow decision.
//
// This extensibility point completes the request flow coverage, allowing extensions
// to make final decisions based on the complete request processing context.
type RequestPostHandler interface {
	// PostHandleRequest is called after the core system processes a request but before
	// the HTTP response is sent.
	//
	// Parameters:
	//   - ctx: Context containing request info and processing result
	//
	// Returns:
	//   - PostHandlerResult: Contains override decision and optional reason
	//   - error: Any error encountered during post-handling
	//
	// If ShouldOverride is true:
	//   - ShouldBlock=true: Force block the request (HTTP 403)
	//   - ShouldBlock=false: Force allow the request (HTTP 200)
	//
	// If ShouldOverride is false:
	//   - The core system's decision is used
	//
	// Note: Post-handlers are invoked in registration order. The first post-handler
	// that returns ShouldOverride=true will determine the final response.
	PostHandleRequest(ctx PostHandlerContext) (PostHandlerResult, error)

	// Name returns a unique identifier for this extension (used for logging and debugging)
	Name() string
}

// RequestLog contains details of a single logged request for pattern analysis
type RequestLog struct {
	URI           string    // The requested URI
	Timestamp     time.Time // When the request occurred
	UserAgent     string    // User-Agent header value
	IsWhitelisted bool      // Whether this request matched whitelist patterns
	Method        string    // HTTP method (GET, POST, etc.)
}

// AnalysisContext provides request history and metadata for pattern analysis
// This is passed to PatternAnalyzer extensions during deferred analysis
type AnalysisContext struct {
	IP           string        // The IP address being analyzed
	RequestLogs  []RequestLog  // All logged requests from this IP
	RequestCount int           // Total request count (same as len(RequestLogs))
	FirstSeen    time.Time     // Timestamp of first request
	LastSeen     time.Time     // Timestamp of last (most recent) request
}

// AnalysisResult contains the verdict from a PatternAnalyzer
type AnalysisResult struct {
	IsSuspicious  bool    // True if suspicious pattern detected
	Reason        string  // Human-readable reason (e.g., "Custom SQL injection pattern")
	SuspiciousURI string  // The specific URI that triggered detection
	Confidence    float64 // Confidence score 0.0-1.0 (optional, for metrics/ML)
}

// StatsDataProvider is the interface that extensions must implement to contribute
// custom data to informational endpoints such as /stats and /events.
//
// Extensions implementing this interface can return arbitrary key-value data that
// will be included in endpoint responses under a namespaced "extensions" field,
// keyed by the provider's Name(). This allows multiple extensions to expose
// custom metrics without polluting the core response structure or requiring
// per-extension endpoints.
//
// # Execution Context
//
// GetStats is called synchronously during /stats HTTP handler and during
// each periodic /events broadcast. Keep implementations fast and avoid
// blocking I/O. Use cached/in-memory data where possible.
//
// # Namespacing
//
// All provider data is nested under "extensions.<Name()>" in the response,
// so different providers cannot conflict with each other or with core fields:
//
//	{
//	  "total_ips": 10,
//	  ...
//	  "extensions": {
//	    "my-extension": { "custom_counter": 42 }
//	  }
//	}
//
// # Error Handling
//
// If GetStats returns an error it is logged and that provider's data is
// omitted from the response (fail-open behaviour). Other providers continue.
type StatsDataProvider interface {
	// GetStats returns a map of custom data to be included in stats/events responses.
	// Keys and values are arbitrary and defined by the extension author.
	// Called on the critical response path - keep it fast.
	GetStats() (map[string]interface{}, error)

	// Name returns a unique identifier for this provider (used as the namespace key)
	Name() string
}

// PatternAnalyzer is the interface for custom pattern detection during deferred analysis.
//
// Extensions implementing this interface can analyze request patterns from an IP
// and decide if the behavior is suspicious. This runs AFTER request logging but
// BEFORE the block decision, allowing custom logic to influence blocking without
// modifying core system code.
//
// # Execution Context
//
// PatternAnalyzers are invoked asynchronously by the analysis worker after an IP
// reaches the analysis threshold (default: 5 requests). They do NOT run on the
// critical request path, so they can perform heavier computation than PreHandleRequest.
//
// # Performance Guidelines
//
//   - Target execution time: <100ms per analysis
//   - Avoid blocking I/O (database calls, external APIs)
//   - Use in-memory pattern matching when possible
//   - Heavy ML models should use local inference, not remote calls
//
// # Multiple Analyzers
//
// When multiple PatternAnalyzers are registered:
//   - Invoked in priority order (lower Priority() value runs first)
//   - First analyzer returning IsSuspicious=true triggers block
//   - Errors are logged but don't prevent other analyzers from running
//   - Block reason will be from the first suspicious analyzer
//
// # Error Handling
//
// Errors returned by AnalyzePattern are logged but do NOT block analysis.
// The system continues with other analyzers and built-in checks (fail-open behavior).
type PatternAnalyzer interface {
	// AnalyzePattern inspects request history and returns suspicion verdict
	//
	// Parameters:
	//   - ctx: Analysis context with request history and metadata
	//
	// Returns:
	//   - AnalysisResult: Contains suspicion verdict and details
	//   - error: Any error encountered during analysis (logged, doesn't block)
	//
	// If IsSuspicious is true, the IP will be blocked for the configured
	// block duration (default: 60 minutes). The Reason field should provide
	// a clear explanation of why the pattern is suspicious.
	AnalyzePattern(ctx AnalysisContext) (AnalysisResult, error)

	// Name returns a unique identifier for this analyzer (used in logging and metrics)
	Name() string

	// Priority returns execution order priority (0=highest, 100=lowest, default 50)
	// Lower values run first, allowing critical checks to preempt others.
	// Use this to ensure high-confidence analyzers run before exploratory ones.
	Priority() int
}
