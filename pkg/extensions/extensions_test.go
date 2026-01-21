package extensions

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockPreHandler is a test implementation of RequestPreHandler
type mockPreHandler struct {
	name         string
	shouldBypass bool
	bypassReason string
	returnError  error
}

func (m *mockPreHandler) Name() string {
	return m.name
}

func (m *mockPreHandler) PreHandleRequest(req RequestInfo) (PreHandlerResult, error) {
	if m.returnError != nil {
		return PreHandlerResult{}, m.returnError
	}

	return PreHandlerResult{
		ShouldBypass: m.shouldBypass,
		Reason:       m.bypassReason,
	}, nil
}

func TestRequestInfoFromHTTP(t *testing.T) {
	req := httptest.NewRequest("GET", "/test/path?query=value", nil)
	req.Header.Set("User-Agent", "test-agent")
	req.Header.Set("X-Custom-Header", "custom-value")

	ip := "192.168.1.1"
	uri := "/test/path"

	info := RequestInfoFromHTTP(req, ip, uri)

	// Verify fields
	if info.IP != ip {
		t.Errorf("Expected IP %s, got %s", ip, info.IP)
	}

	if info.URI != uri {
		t.Errorf("Expected URI %s, got %s", uri, info.URI)
	}

	if info.UserAgent != "test-agent" {
		t.Errorf("Expected UserAgent 'test-agent', got %s", info.UserAgent)
	}

	if info.Method != "GET" {
		t.Errorf("Expected Method 'GET', got %s", info.Method)
	}

	// Check headers
	if len(info.Headers["User-Agent"]) == 0 || info.Headers["User-Agent"][0] != "test-agent" {
		t.Errorf("Expected User-Agent header 'test-agent', got %v", info.Headers["User-Agent"])
	}

	if len(info.Headers["X-Custom-Header"]) == 0 || info.Headers["X-Custom-Header"][0] != "custom-value" {
		t.Errorf("Expected X-Custom-Header 'custom-value', got %v", info.Headers["X-Custom-Header"])
	}
}

func TestMockPreHandler_Name(t *testing.T) {
	handler := &mockPreHandler{name: "test-handler"}

	if handler.Name() != "test-handler" {
		t.Errorf("Expected name 'test-handler', got %s", handler.Name())
	}
}

func TestMockPreHandler_PreHandleRequest_Bypass(t *testing.T) {
	handler := &mockPreHandler{
		name:         "bypass-handler",
		shouldBypass: true,
		bypassReason: "testing bypass",
	}

	req := RequestInfo{
		IP:        "10.0.0.1",
		URI:       "/test",
		UserAgent: "test",
		Method:    "GET",
	}

	result, err := handler.PreHandleRequest(req)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !result.ShouldBypass {
		t.Error("Expected ShouldBypass to be true")
	}

	if result.Reason != "testing bypass" {
		t.Errorf("Expected reason 'testing bypass', got %s", result.Reason)
	}
}

func TestMockPreHandler_PreHandleRequest_NoByppass(t *testing.T) {
	handler := &mockPreHandler{
		name:         "no-bypass-handler",
		shouldBypass: false,
	}

	req := RequestInfo{
		IP:        "10.0.0.2",
		URI:       "/test",
		UserAgent: "test",
		Method:    "GET",
	}

	result, err := handler.PreHandleRequest(req)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if result.ShouldBypass {
		t.Error("Expected ShouldBypass to be false")
	}
}

func TestMockPreHandler_PreHandleRequest_Error(t *testing.T) {
	testErr := http.ErrServerClosed
	handler := &mockPreHandler{
		name:        "error-handler",
		returnError: testErr,
	}

	req := RequestInfo{
		IP:        "10.0.0.3",
		URI:       "/test",
		UserAgent: "test",
		Method:    "GET",
	}

	result, err := handler.PreHandleRequest(req)

	if err != testErr {
		t.Errorf("Expected error %v, got %v", testErr, err)
	}

	// Result should be zero value when error returned
	if result.ShouldBypass {
		t.Error("Expected ShouldBypass to be false on error")
	}
}

// Example of a simple IP allowlist extension for testing
type IPAllowlistExtension struct {
	allowedIPs map[string]bool
}

func NewIPAllowlistExtension(ips []string) *IPAllowlistExtension {
	allowed := make(map[string]bool)
	for _, ip := range ips {
		allowed[ip] = true
	}
	return &IPAllowlistExtension{allowedIPs: allowed}
}

func (e *IPAllowlistExtension) Name() string {
	return "ip-allowlist"
}

func (e *IPAllowlistExtension) PreHandleRequest(req RequestInfo) (PreHandlerResult, error) {
	if e.allowedIPs[req.IP] {
		return PreHandlerResult{
			ShouldBypass: true,
			Reason:       "IP on allowlist",
		}, nil
	}

	return PreHandlerResult{ShouldBypass: false}, nil
}

func TestIPAllowlistExtension(t *testing.T) {
	ext := NewIPAllowlistExtension([]string{"10.0.0.1", "192.168.1.1"})

	tests := []struct {
		name           string
		ip             string
		expectedBypass bool
		expectedReason string
	}{
		{
			name:           "Allowed IP",
			ip:             "10.0.0.1",
			expectedBypass: true,
			expectedReason: "IP on allowlist",
		},
		{
			name:           "Another allowed IP",
			ip:             "192.168.1.1",
			expectedBypass: true,
			expectedReason: "IP on allowlist",
		},
		{
			name:           "Not allowed IP",
			ip:             "1.2.3.4",
			expectedBypass: false,
			expectedReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := RequestInfo{
				IP:     tt.ip,
				URI:    "/test",
				Method: "GET",
			}

			result, err := ext.PreHandleRequest(req)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if result.ShouldBypass != tt.expectedBypass {
				t.Errorf("Expected ShouldBypass=%v, got %v", tt.expectedBypass, result.ShouldBypass)
			}

			if result.Reason != tt.expectedReason {
				t.Errorf("Expected reason '%s', got '%s'", tt.expectedReason, result.Reason)
			}
		})
	}
}

// Mock PatternAnalyzer for testing
type mockPatternAnalyzer struct {
	name              string
	priority          int
	shouldBeSuspicious bool
	returnError       error
	confidence        float64
	reason            string
	suspiciousURI     string
}

func (m *mockPatternAnalyzer) AnalyzePattern(ctx AnalysisContext) (AnalysisResult, error) {
	if m.returnError != nil {
		return AnalysisResult{}, m.returnError
	}

	return AnalysisResult{
		IsSuspicious:  m.shouldBeSuspicious,
		Reason:        m.reason,
		SuspiciousURI: m.suspiciousURI,
		Confidence:    m.confidence,
	}, nil
}

func (m *mockPatternAnalyzer) Name() string {
	return m.name
}

func (m *mockPatternAnalyzer) Priority() int {
	return m.priority
}

func TestAnalysisContext(t *testing.T) {
	now := time.Now()
	logs := []RequestLog{
		{
			URI:           "/api/users",
			Timestamp:     now,
			UserAgent:     "agent1",
			IsWhitelisted: false,
			Method:        "GET",
		},
		{
			URI:           "/api/products",
			Timestamp:     now.Add(1 * time.Second),
			UserAgent:     "agent1",
			IsWhitelisted: false,
			Method:        "POST",
		},
	}

	ctx := AnalysisContext{
		IP:           "10.0.0.1",
		RequestLogs:  logs,
		RequestCount: 2,
		FirstSeen:    now,
		LastSeen:     now.Add(1 * time.Second),
	}

	if ctx.IP != "10.0.0.1" {
		t.Errorf("Expected IP 10.0.0.1, got %s", ctx.IP)
	}

	if ctx.RequestCount != 2 {
		t.Errorf("Expected RequestCount 2, got %d", ctx.RequestCount)
	}

	if len(ctx.RequestLogs) != 2 {
		t.Errorf("Expected 2 request logs, got %d", len(ctx.RequestLogs))
	}

	if ctx.RequestLogs[0].URI != "/api/users" {
		t.Errorf("Expected first URI /api/users, got %s", ctx.RequestLogs[0].URI)
	}

	if ctx.RequestLogs[1].Method != "POST" {
		t.Errorf("Expected second method POST, got %s", ctx.RequestLogs[1].Method)
	}
}

func TestAnalysisResult(t *testing.T) {
	result := AnalysisResult{
		IsSuspicious:  true,
		Reason:        "Test reason",
		SuspiciousURI: "/malicious/path",
		Confidence:    0.95,
	}

	if !result.IsSuspicious {
		t.Error("Expected IsSuspicious to be true")
	}

	if result.Reason != "Test reason" {
		t.Errorf("Expected Reason 'Test reason', got %s", result.Reason)
	}

	if result.SuspiciousURI != "/malicious/path" {
		t.Errorf("Expected SuspiciousURI /malicious/path, got %s", result.SuspiciousURI)
	}

	if result.Confidence != 0.95 {
		t.Errorf("Expected Confidence 0.95, got %.2f", result.Confidence)
	}
}

func TestMockPatternAnalyzer_Normal(t *testing.T) {
	analyzer := &mockPatternAnalyzer{
		name:               "test-analyzer",
		priority:           50,
		shouldBeSuspicious: true,
		confidence:         0.85,
		reason:             "Test pattern detected",
		suspiciousURI:      "/test/malicious",
	}

	if analyzer.Name() != "test-analyzer" {
		t.Errorf("Expected name test-analyzer, got %s", analyzer.Name())
	}

	if analyzer.Priority() != 50 {
		t.Errorf("Expected priority 50, got %d", analyzer.Priority())
	}

	now := time.Now()
	ctx := AnalysisContext{
		IP:           "10.0.0.1",
		RequestCount: 5,
		RequestLogs: []RequestLog{
			{URI: "/test/malicious", Timestamp: now, Method: "GET"},
		},
		FirstSeen: now,
		LastSeen:  now,
	}

	result, err := analyzer.AnalyzePattern(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !result.IsSuspicious {
		t.Error("Expected IsSuspicious to be true")
	}

	if result.Confidence != 0.85 {
		t.Errorf("Expected confidence 0.85, got %.2f", result.Confidence)
	}

	if result.Reason != "Test pattern detected" {
		t.Errorf("Expected reason 'Test pattern detected', got %s", result.Reason)
	}

	if result.SuspiciousURI != "/test/malicious" {
		t.Errorf("Expected SuspiciousURI '/test/malicious', got %s", result.SuspiciousURI)
	}
}

func TestMockPatternAnalyzer_NotSuspicious(t *testing.T) {
	analyzer := &mockPatternAnalyzer{
		name:               "clean-analyzer",
		priority:           10,
		shouldBeSuspicious: false,
		confidence:         0.10,
	}

	ctx := AnalysisContext{
		IP:           "10.0.0.2",
		RequestCount: 3,
	}

	result, err := analyzer.AnalyzePattern(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if result.IsSuspicious {
		t.Error("Expected IsSuspicious to be false")
	}

	if result.Confidence != 0.10 {
		t.Errorf("Expected confidence 0.10, got %.2f", result.Confidence)
	}
}

func TestMockPatternAnalyzer_Error(t *testing.T) {
	testErr := errors.New("mock analysis error")
	analyzer := &mockPatternAnalyzer{
		name:        "error-analyzer",
		priority:    10,
		returnError: testErr,
	}

	ctx := AnalysisContext{
		IP:           "10.0.0.1",
		RequestCount: 5,
	}

	_, err := analyzer.AnalyzePattern(ctx)
	if err == nil {
		t.Error("Expected error but got nil")
	}

	if err.Error() != "mock analysis error" {
		t.Errorf("Expected error 'mock analysis error', got %s", err.Error())
	}
}

func TestMockPatternAnalyzer_PriorityOrdering(t *testing.T) {
	analyzers := []PatternAnalyzer{
		&mockPatternAnalyzer{name: "low", priority: 100},
		&mockPatternAnalyzer{name: "high", priority: 10},
		&mockPatternAnalyzer{name: "medium", priority: 50},
	}

	// In production, these would be sorted by RegisterPatternAnalyzer
	// Test that priority values are correctly set
	if analyzers[0].Priority() != 100 {
		t.Errorf("Expected priority 100, got %d", analyzers[0].Priority())
	}

	if analyzers[1].Priority() != 10 {
		t.Errorf("Expected priority 10, got %d", analyzers[1].Priority())
	}

	if analyzers[2].Priority() != 50 {
		t.Errorf("Expected priority 50, got %d", analyzers[2].Priority())
	}
}

