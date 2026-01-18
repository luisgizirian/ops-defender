package extensions

import "net/http"

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
