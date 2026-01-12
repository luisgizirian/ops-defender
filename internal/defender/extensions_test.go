package defender

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ops/defender/extension-points"
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
