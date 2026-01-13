package defender

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	extensions "github.com/ops/defender/extension-points"
	"github.com/ops/defender/internal/storage"
)

// TestPatternProvider for testing
type TestPatternProvider struct {
	name     string
	patterns []string
	priority int
}

func (t *TestPatternProvider) GetPatterns() []string {
	return t.patterns
}

func (t *TestPatternProvider) GetName() string {
	return t.name
}

func (t *TestPatternProvider) GetPriority() int {
	return t.priority
}

// TestBlockingRuleProvider for testing
type TestBlockingRuleProvider struct {
	name      string
	priority  int
	threshold int // Block if request count exceeds this
}

func (t *TestBlockingRuleProvider) ShouldBlock(ip string, requestCount int, requestLogs []extensions.RequestLogInfo) (bool, string) {
	if requestCount > t.threshold {
		return true, "custom threshold exceeded"
	}
	return false, ""
}

func (t *TestBlockingRuleProvider) GetName() string {
	return t.name
}

func (t *TestBlockingRuleProvider) GetPriority() int {
	return t.priority
}

// TestWhitelistProvider for testing
type TestWhitelistProvider struct {
	name     string
	patterns []string
	priority int
}

func (t *TestWhitelistProvider) GetWhitelistPatterns() []string {
	return t.patterns
}

func (t *TestWhitelistProvider) GetName() string {
	return t.name
}

func (t *TestWhitelistProvider) GetPriority() int {
	return t.priority
}

func TestDefender_ExtensionPatternProvider(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	
	// Create extension registry and register custom pattern provider
	registry := extensions.NewExtensionRegistry()
	registry.RegisterPatternProvider(&TestPatternProvider{
		name:     "Test Custom Patterns",
		patterns: []string{`/custom-admin`, `/secret-endpoint`},
		priority: 0,
	})
	
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    3,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
		ExtensionRegistry:    registry,
	})

	ip := "192.168.1.200"
	
	// Send requests to custom pattern endpoints
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Original-URI", "/custom-admin/settings")

		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)
		
		// First requests are allowed (deferred analysis)
		if w.Code != http.StatusOK {
			t.Errorf("Expected first requests to be allowed, got %d", w.Code)
		}
	}
	
	// Wait for analysis
	time.Sleep(100 * time.Millisecond)
	
	// Subsequent request should be blocked
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", ip)
	req.Header.Set("X-Original-URI", "/any-path")
	
	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)
	
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected IP to be blocked due to custom pattern, got %d", w.Code)
	}
}

func TestDefender_ExtensionBlockingRuleProvider(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	
	// Create extension registry and register custom blocking rule
	registry := extensions.NewExtensionRegistry()
	registry.RegisterBlockingRuleProvider(&TestBlockingRuleProvider{
		name:      "Custom Threshold Rule",
		priority:  0,
		threshold: 7, // Block after 7 requests
	})
	
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    5,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
		ExtensionRegistry:    registry,
	})

	ip := "192.168.1.201"
	
	// Send 8 normal requests (not matching any suspicious pattern)
	for i := 0; i < 8; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Original-URI", "/normal-path")

		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)
		
		// First 5 requests are always allowed
		if i < 5 && w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected to be allowed, got %d", i, w.Code)
		}
	}
	
	// Wait for analysis (happens at request 5)
	time.Sleep(100 * time.Millisecond)
	
	// Next request should be blocked (we have 8 requests > threshold of 7)
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", ip)
	req.Header.Set("X-Original-URI", "/normal-path")
	
	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)
	
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected IP to be blocked by custom rule, got %d", w.Code)
	}
}

func TestDefender_ExtensionWhitelistProvider(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	
	// Create extension registry and register custom whitelist
	registry := extensions.NewExtensionRegistry()
	registry.RegisterWhitelistProvider(&TestWhitelistProvider{
		name:     "Custom Whitelist",
		patterns: []string{`^/custom-public/.*\.js$`},
		priority: 0,
	})
	
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    3,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
		ExtensionRegistry:    registry,
	})

	ip := "192.168.1.202"
	
	// Send requests to custom whitelisted paths
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Original-URI", "/custom-public/app.js")

		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)
		
		// All whitelisted requests should be allowed
		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected whitelisted request to be allowed, got %d", i, w.Code)
		}
	}
	
	// Wait for any analysis
	time.Sleep(100 * time.Millisecond)
	
	// Whitelisted paths should still be allowed
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", ip)
	req.Header.Set("X-Original-URI", "/custom-public/main.js")
	
	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected custom whitelisted request to remain allowed, got %d", w.Code)
	}
}

func TestDefender_ExtensionPriority(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	
	// Create extension registry with multiple providers
	registry := extensions.NewExtensionRegistry()
	
	// Low priority provider
	registry.RegisterPatternProvider(&TestPatternProvider{
		name:     "Low Priority",
		patterns: []string{`/low-priority`},
		priority: 0,
	})
	
	// High priority provider
	registry.RegisterPatternProvider(&TestPatternProvider{
		name:     "High Priority",
		patterns: []string{`/high-priority`},
		priority: 100,
	})
	
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    3,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
		ExtensionRegistry:    registry,
	})

	// Verify patterns were loaded
	if len(defender.suspiciousPatterns) == 0 {
		t.Error("Expected extension patterns to be loaded")
	}
}

func TestDefender_NoExtensionRegistry(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	
	// Create defender without extension registry
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    3,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
		ExtensionRegistry:    nil, // No extensions
	})

	// Should work fine without extensions
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "192.168.1.203")
	req.Header.Set("X-Original-URI", "/normal-path")

	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected request to be allowed without extensions, got %d", w.Code)
	}
}

// TestPreRequestHandler for testing early request interception
type TestPreRequestHandler struct {
	name         string
	priority     int
	shouldTerminate bool
	callCount    int
}

func (t *TestPreRequestHandler) Handle(ip, uri, userAgent string) extensions.RequestAction {
	t.callCount++
	if t.shouldTerminate {
		return extensions.Terminate
	}
	return extensions.Continue
}

func (t *TestPreRequestHandler) GetName() string {
	return t.name
}

func (t *TestPreRequestHandler) GetPriority() int {
	return t.priority
}

// TestPostRequestHandler for testing late request interception
type TestPostRequestHandler struct {
	name         string
	priority     int
	shouldTerminate bool
	callCount    int
	lastRequestCount int
}

func (t *TestPostRequestHandler) Handle(ip, uri, userAgent string, requestCount int) extensions.RequestAction {
	t.callCount++
	t.lastRequestCount = requestCount
	if t.shouldTerminate {
		return extensions.Terminate
	}
	return extensions.Continue
}

func (t *TestPostRequestHandler) GetName() string {
	return t.name
}

func (t *TestPostRequestHandler) GetPriority() int {
	return t.priority
}

func TestDefender_PreRequestHandler_Continue(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	
	preHandler := &TestPreRequestHandler{
		name:         "Test Pre-Handler",
		priority:     0,
		shouldTerminate: false,
	}
	
	registry := extensions.NewExtensionRegistry()
	registry.RegisterPreRequestHandler(preHandler)
	
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    3,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
		ExtensionRegistry:    registry,
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "192.168.1.204")
	req.Header.Set("X-Original-URI", "/normal-path")

	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected request to be allowed, got %d", w.Code)
	}
	
	if preHandler.callCount != 1 {
		t.Errorf("Expected pre-handler to be called once, got %d", preHandler.callCount)
	}
}

func TestDefender_PreRequestHandler_Terminate(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	
	preHandler := &TestPreRequestHandler{
		name:         "Test Pre-Handler Terminate",
		priority:     0,
		shouldTerminate: true,
	}
	
	registry := extensions.NewExtensionRegistry()
	registry.RegisterPreRequestHandler(preHandler)
	
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    3,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
		ExtensionRegistry:    registry,
	})

	ip := "192.168.1.205"
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", ip)
	req.Header.Set("X-Original-URI", "/normal-path")

	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)
	
	// Pre-handler terminated, should return 200 OK
	if w.Code != http.StatusOK {
		t.Errorf("Expected request to be allowed after pre-handler terminate, got %d", w.Code)
	}
	
	if preHandler.callCount != 1 {
		t.Errorf("Expected pre-handler to be called once, got %d", preHandler.callCount)
	}
	
	// Verify IP was NOT logged (pre-handler terminated before logging)
	defender.mu.RLock()
	_, tracked := defender.ipTrackers[ip]
	defender.mu.RUnlock()
	
	if tracked {
		t.Error("Expected IP to NOT be tracked after pre-handler terminate")
	}
}

func TestDefender_PostRequestHandler_Continue(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	
	postHandler := &TestPostRequestHandler{
		name:         "Test Post-Handler",
		priority:     0,
		shouldTerminate: false,
	}
	
	registry := extensions.NewExtensionRegistry()
	registry.RegisterPostRequestHandler(postHandler)
	
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    3,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
		ExtensionRegistry:    registry,
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "192.168.1.206")
	req.Header.Set("X-Original-URI", "/normal-path")

	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected request to be allowed, got %d", w.Code)
	}
	
	if postHandler.callCount != 1 {
		t.Errorf("Expected post-handler to be called once, got %d", postHandler.callCount)
	}
	
	if postHandler.lastRequestCount != 1 {
		t.Errorf("Expected requestCount to be 1, got %d", postHandler.lastRequestCount)
	}
}

func TestDefender_PreAndPostHandlers_Together(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	
	preHandler := &TestPreRequestHandler{
		name:         "Test Pre",
		priority:     0,
		shouldTerminate: false,
	}
	
	postHandler := &TestPostRequestHandler{
		name:         "Test Post",
		priority:     0,
		shouldTerminate: false,
	}
	
	registry := extensions.NewExtensionRegistry()
	registry.RegisterPreRequestHandler(preHandler)
	registry.RegisterPostRequestHandler(postHandler)
	
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    3,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
		ExtensionRegistry:    registry,
	})

	ip := "192.168.1.207"
	
	// Send 3 requests
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Original-URI", "/normal-path")

		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected to be allowed, got %d", i, w.Code)
		}
	}
	
	// Both handlers should be called 3 times
	if preHandler.callCount != 3 {
		t.Errorf("Expected pre-handler to be called 3 times, got %d", preHandler.callCount)
	}
	
	if postHandler.callCount != 3 {
		t.Errorf("Expected post-handler to be called 3 times, got %d", postHandler.callCount)
	}
	
	// Last request count should be 3
	if postHandler.lastRequestCount != 3 {
		t.Errorf("Expected last requestCount to be 3, got %d", postHandler.lastRequestCount)
	}
}

func TestDefender_HandlerPriority(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	
	// Create handlers with different priorities
	lowPriorityPre := &TestPreRequestHandler{
		name:         "Low Priority Pre",
		priority:     0,
		shouldTerminate: false,
	}
	
	highPriorityPre := &TestPreRequestHandler{
		name:         "High Priority Pre",
		priority:     100,
		shouldTerminate: true, // This should terminate first
	}
	
	registry := extensions.NewExtensionRegistry()
	registry.RegisterPreRequestHandler(lowPriorityPre)
	registry.RegisterPreRequestHandler(highPriorityPre)
	
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    3,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
		ExtensionRegistry:    registry,
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "192.168.1.208")
	req.Header.Set("X-Original-URI", "/normal-path")

	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)
	
	// High priority handler should terminate, preventing low priority from running
	if highPriorityPre.callCount != 1 {
		t.Errorf("Expected high priority pre-handler to be called, got %d", highPriorityPre.callCount)
	}
	
	if lowPriorityPre.callCount != 0 {
		t.Errorf("Expected low priority pre-handler to NOT be called (terminated by high priority), got %d", lowPriorityPre.callCount)
	}
}

func TestDefender_NoHandlersRegistered(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	
	// Create defender without any handlers registered
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    3,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
		ExtensionRegistry:    nil,
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "192.168.1.209")
	req.Header.Set("X-Original-URI", "/normal-path")

	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)
	
	// Should work normally without any handlers
	if w.Code != http.StatusOK {
		t.Errorf("Expected request to be allowed without handlers, got %d", w.Code)
	}
}
