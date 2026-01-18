package extensions

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
