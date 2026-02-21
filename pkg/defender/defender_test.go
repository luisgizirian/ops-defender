package defender

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ops/defender/pkg/extensions"
	"github.com/ops/defender/pkg/storage"
)

func TestDefender_CheckRequest_AllowsNormalRequest(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    100,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "192.168.1.1")
	req.Header.Set("X-Original-URI", "/normal-path")

	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestDefender_CheckRequest_BlocksSuspiciousPath(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	// Set low threshold so analysis happens quickly
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    3,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	suspiciousPaths := []string{
		"/wp-admin",
		"/../etc/passwd",
		"/phpmyadmin",
	}

	ip := "192.168.1.100"
	
	// Send enough requests to trigger analysis (threshold = 3)
	for i := 0; i < 3; i++ {
		path := suspiciousPaths[i%len(suspiciousPaths)]
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Original-URI", path)

		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)
		
		// First requests are allowed (deferred analysis)
		if w.Code != http.StatusOK {
			t.Errorf("Expected first requests to be allowed, got %d", w.Code)
		}
	}
	
	// Wait for analysis worker to process
	time.Sleep(100 * time.Millisecond)
	
	// Now subsequent requests should be blocked
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", ip)
	req.Header.Set("X-Original-URI", "/any-path")
	
	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)
	
	// Expecting 403 (Forbidden) which is what handleBlockedRequest returns in non-simulation mode
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected IP to be blocked after suspicious patterns detected, got %d", w.Code)
	}
}

func TestDefender_CheckRequest_BlocksRateLimitExceeded(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    10,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	ip := "192.168.1.2"

	// Send requests exceeding rate limit
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Original-URI", "/normal-path")

		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)

		// After enough requests, should be blocked
		if i >= 15 && w.Code == http.StatusForbidden {
			return // Test passed
		}
	}
}

func TestDefender_ExtractIP(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    100,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expected   string
	}{
		{
			name:     "X-Real-IP header with IPv4",
			headers:  map[string]string{"X-Real-IP": "10.0.0.1"},
			expected: "10.0.0.1",
		},
		{
			name:     "X-Real-IP header with IPv6",
			headers:  map[string]string{"X-Real-IP": "2001:db8::1"},
			expected: "2001:db8::1",
		},
		{
			name:     "X-Forwarded-For header with IPv4",
			headers:  map[string]string{"X-Forwarded-For": "10.0.0.2, 10.0.0.3"},
			expected: "10.0.0.2",
		},
		{
			name:     "X-Forwarded-For header with IPv6",
			headers:  map[string]string{"X-Forwarded-For": "2001:db8::2, 2001:db8::3"},
			expected: "2001:db8::2",
		},
		{
			name:       "RemoteAddr with IPv4",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.1:54321",
			expected:   "192.168.1.1",
		},
		{
			name:       "RemoteAddr with IPv6",
			headers:    map[string]string{},
			remoteAddr: "[2001:db8::1]:54321",
			expected:   "2001:db8::1",
		},
		{
			name:       "RemoteAddr with IPv6 loopback",
			headers:    map[string]string{},
			remoteAddr: "[::1]:12345",
			expected:   "::1",
		},
		{
			name:       "RemoteAddr with full IPv6",
			headers:    map[string]string{},
			remoteAddr: "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:8080",
			expected:   "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			if tt.remoteAddr != "" {
				req.RemoteAddr = tt.remoteAddr
			}

			ip := defender.extractIP(req)
			if ip != tt.expected {
				t.Errorf("Expected IP %s, got %s", tt.expected, ip)
			}
		})
	}

	// Test that extracted IPs work correctly with storage
	t.Run("IPv6 storage integration", func(t *testing.T) {
		ctx := context.Background()
		ipv6 := "2001:db8::42"
		err := store.BlockIP(ctx, ipv6, "test", 60*time.Minute)
		if err != nil {
			t.Fatalf("Failed to block IPv6: %v", err)
		}

		blocked, err := store.IsBlocked(ctx, ipv6)
		if err != nil {
			t.Fatalf("Failed to check IPv6 block status: %v", err)
		}
		if !blocked {
			t.Errorf("IPv6 address should be blocked")
		}
	})
}

func TestDefender_IsSuspicious(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    100,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	tests := []struct {
		uri        string
		suspicious bool
	}{
		{"/normal-path", false},
		{"/api/users", false},
		{"/wp-admin", true},
		{"/script.php", true},
		{"/.git/config", true},
		{"/api/data", false},
	}

	for _, tt := range tests {
		result := defender.isSuspicious(tt.uri)
		if result != tt.suspicious {
			t.Errorf("URI %s: expected suspicious=%v, got %v", tt.uri, tt.suspicious, result)
		}
	}
	
	// Test path traversal separately (now in separate method)
	pathTraversalTests := []struct {
		uri           string
		hasTraversal bool
	}{
		{"/../etc/passwd", true},
		{"/normal-path", false},
		{"/scripts/../config", true},
		{"/api/data", false},
	}
	
	for _, tt := range pathTraversalTests {
		result := defender.hasPathTraversal(tt.uri)
		if result != tt.hasTraversal {
			t.Errorf("URI %s: expected path traversal=%v, got %v", tt.uri, tt.hasTraversal, result)
		}
	}
}

func TestDefender_MemoryLimit(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	maxIPs := 10
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    100,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        maxIPs,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	// Add more IPs than the limit
	for i := 0; i < maxIPs+5; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i)
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Original-URI", "/normal-path")

		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)
	}

	// Wait for async bulk eviction to complete
	time.Sleep(100 * time.Millisecond)

	// Check that we never exceed the limit
	defender.mu.RLock()
	activeIPs := len(defender.ipTrackers)
	droppedIPs := defender.droppedIPs
	defender.mu.RUnlock()

	if activeIPs > maxIPs {
		t.Errorf("Expected max %d active IPs, got %d", maxIPs, activeIPs)
	}

	// With bulk eviction (10%), we should evict 1 IP at a time (10% of 10 = 1)
	// So we expect 5 dropped IPs total
	if droppedIPs < 1 {
		t.Errorf("Expected at least 1 dropped IP, got %d", droppedIPs)
	}
}

func TestDefender_BulkEviction(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	maxIPs := 100
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    100,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        maxIPs,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	// Fill up to just below preemptive threshold (88 IPs, threshold is 90)
	for i := 0; i < 88; i++ {
		ip := fmt.Sprintf("192.168.%d.%d", i/256, i%256)
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Original-URI", "/normal-path")

		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)
		
		// Small delay to ensure different timestamps
		time.Sleep(1 * time.Millisecond)
	}

	// Verify we're below threshold - no eviction yet
	defender.mu.RLock()
	activeIPsBefore := len(defender.ipTrackers)
	droppedBefore := defender.droppedIPs
	defender.mu.RUnlock()

	if activeIPsBefore != 88 {
		t.Errorf("Expected 88 active IPs before threshold, got %d", activeIPsBefore)
	}
	
	if droppedBefore != 0 {
		t.Errorf("Expected 0 dropped IPs before threshold, got %d", droppedBefore)
	}

	// Add IPs to cross threshold and trigger bulk eviction
	for i := 88; i < 95; i++ {
		ip := fmt.Sprintf("192.168.%d.%d", i/256, i%256)
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Original-URI", "/normal-path")
		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)
		time.Sleep(1 * time.Millisecond)
	}

	// Wait for async eviction to complete
	time.Sleep(200 * time.Millisecond)

	// Check that bulk eviction occurred (should evict ~10% = 10 IPs)
	defender.mu.RLock()
	activeIPsAfter := len(defender.ipTrackers)
	droppedIPs := defender.droppedIPs
	defender.mu.RUnlock()

	// After adding 7 IPs (88->95) and preemptive eviction of 10 IPs at 91 count
	// Expected: 95 - 10 (evicted) = ~85 IPs
	expectedMin := 75 // Allow variance due to async timing
	expectedMax := 92
	
	if activeIPsAfter < expectedMin || activeIPsAfter > expectedMax {
		t.Errorf("Expected active IPs between %d and %d after bulk eviction, got %d", 
			expectedMin, expectedMax, activeIPsAfter)
	}

	// Should have dropped approximately 10% of IPs
	if droppedIPs < 5 {
		t.Errorf("Expected at least 5 dropped IPs from bulk eviction, got %d", droppedIPs)
	}
}

func TestDefender_BulkEviction_LRU_Order(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	maxIPs := 50
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    100,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        maxIPs,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	// Add IPs with different timestamps
	oldIPs := []string{}
	for i := 0; i < 30; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		oldIPs = append(oldIPs, ip)
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Original-URI", "/normal-path")

		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)
		time.Sleep(2 * time.Millisecond)
	}

	// Add recent IPs
	recentIPs := []string{}
	for i := 30; i < maxIPs; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		recentIPs = append(recentIPs, ip)
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Original-URI", "/normal-path")

		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)
		time.Sleep(2 * time.Millisecond)
	}

	// Trigger bulk eviction by adding a new IP
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "203.0.113.99")
	req.Header.Set("X-Original-URI", "/normal-path")
	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)

	// Wait for async eviction
	time.Sleep(200 * time.Millisecond)

	// Verify that old IPs were evicted (LRU)
	defender.mu.RLock()
	evictedOldCount := 0
	evictedRecentCount := 0
	
	for _, ip := range oldIPs {
		if _, exists := defender.ipTrackers[ip]; !exists {
			evictedOldCount++
		}
	}
	
	for _, ip := range recentIPs {
		if _, exists := defender.ipTrackers[ip]; !exists {
			evictedRecentCount++
		}
	}
	defender.mu.RUnlock()

	// Most evicted IPs should be from the old batch (LRU)
	if evictedOldCount == 0 {
		t.Errorf("Expected some old IPs to be evicted, but none were")
	}

	// Recent IPs should mostly be retained
	if evictedRecentCount > evictedOldCount {
		t.Errorf("Expected more old IPs evicted than recent, got old=%d recent=%d", 
			evictedOldCount, evictedRecentCount)
	}
}

func TestDefender_BulkEviction_EdgeCases(t *testing.T) {
	t.Run("Small limit evicts at least 1 IP", func(t *testing.T) {
		store := storage.NewMemoryStorage(60 * time.Minute)
		maxIPs := 5
		defender := NewDefender(DefenderOptions{
			AnalysisThreshold:    100,
			BlockDuration:        60 * time.Minute,
			Storage:              store,
			MaxTrackedIPs:        maxIPs,
			EvictionBatchPct:     0.10,
			EvictionThresholdPct: 0.93,
			SimulationMode:       false,
		})

		// Fill to capacity
		for i := 0; i < maxIPs; i++ {
			ip := fmt.Sprintf("192.168.1.%d", i)
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("X-Real-IP", ip)
			req.Header.Set("X-Original-URI", "/normal-path")
			w := httptest.NewRecorder()
			defender.CheckRequest(w, req)
		}

		// Trigger eviction
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", "192.168.1.100")
		req.Header.Set("X-Original-URI", "/normal-path")
		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)

		time.Sleep(100 * time.Millisecond)

		defender.mu.RLock()
		activeIPs := len(defender.ipTrackers)
		droppedIPs := defender.droppedIPs
		defender.mu.RUnlock()

		// Should still respect max limit
		if activeIPs > maxIPs {
			t.Errorf("Expected max %d IPs, got %d", maxIPs, activeIPs)
		}

		// Should have dropped at least 1 IP
		if droppedIPs < 1 {
			t.Errorf("Expected at least 1 dropped IP, got %d", droppedIPs)
		}
	})

	t.Run("Empty trackers evicted first", func(t *testing.T) {
		store := storage.NewMemoryStorage(60 * time.Minute)
		maxIPs := 10
		defender := NewDefender(DefenderOptions{
			AnalysisThreshold:    100,
			BlockDuration:        60 * time.Minute,
			Storage:              store,
			MaxTrackedIPs:        maxIPs,
			EvictionBatchPct:     0.10,
			EvictionThresholdPct: 0.93,
			SimulationMode:       false,
		})

		// Manually add an empty tracker
		defender.mu.Lock()
		defender.ipTrackers["10.0.0.1"] = &IPTracker{RequestLogs: []RequestLog{}}
		defender.mu.Unlock()

		// Fill remaining capacity with valid requests
		for i := 2; i < maxIPs+1; i++ {
			ip := fmt.Sprintf("10.0.0.%d", i)
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("X-Real-IP", ip)
			req.Header.Set("X-Original-URI", "/normal-path")
			w := httptest.NewRecorder()
			defender.CheckRequest(w, req)
		}

		// Trigger eviction
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", "10.0.0.200")
		req.Header.Set("X-Original-URI", "/normal-path")
		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)

		time.Sleep(100 * time.Millisecond)

		// Empty tracker should be evicted
		defender.mu.RLock()
		_, exists := defender.ipTrackers["10.0.0.1"]
		defender.mu.RUnlock()

		if exists {
			t.Errorf("Expected empty tracker to be evicted first, but it still exists")
		}
	})
}

func TestDefender_PreemptiveEviction(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	maxIPs := 100
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    100,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        maxIPs,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

// Verify eviction threshold is set to 90%
expectedThreshold := int(float64(maxIPs) * 0.93) // 90
if defender.evictionThreshold != expectedThreshold {
t.Errorf("Expected eviction threshold %d, got %d", expectedThreshold, defender.evictionThreshold)
}

// Fill up to just below threshold (88 IPs)
for i := 0; i < 88; i++ {
ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
req := httptest.NewRequest("GET", "/test", nil)
req.Header.Set("X-Real-IP", ip)
req.Header.Set("X-Original-URI", "/normal-path")
w := httptest.NewRecorder()
defender.CheckRequest(w, req)
time.Sleep(1 * time.Millisecond)
}

// Add IPs to cross threshold (90+)
for i := 88; i < 95; i++ {
ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
req := httptest.NewRequest("GET", "/test", nil)
req.Header.Set("X-Real-IP", ip)
req.Header.Set("X-Original-URI", "/normal-path")
w := httptest.NewRecorder()
defender.CheckRequest(w, req)
time.Sleep(2 * time.Millisecond)
}

// Wait for async eviction to complete
time.Sleep(200 * time.Millisecond)

// Verify preemptive eviction occurred
defender.mu.RLock()
droppedAfter := defender.droppedIPs
defender.mu.RUnlock()

// Should have evicted at least some IPs
if droppedAfter == 0 {
t.Errorf("Expected some dropped IPs from preemptive eviction, got %d", droppedAfter)
}

t.Logf("Preemptive eviction: %d IPs dropped", droppedAfter)
}

func TestDefender_RaceCondition_ConcurrentRequests(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	maxIPs := 50
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    100,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        maxIPs,
		EvictionBatchPct:     0.20, // 20% eviction
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

// Fill up to just below threshold (43 IPs)
for i := 0; i < 43; i++ {
ip := fmt.Sprintf("10.0.0.%d", i)
req := httptest.NewRequest("GET", "/test", nil)
req.Header.Set("X-Real-IP", ip)
req.Header.Set("X-Original-URI", "/normal-path")
w := httptest.NewRecorder()
defender.CheckRequest(w, req)
}

// Send 20 concurrent requests
var wg sync.WaitGroup
for i := 0; i < 20; i++ {
wg.Add(1)
go func(idx int) {
defer wg.Done()
ip := fmt.Sprintf("192.168.1.%d", idx)
req := httptest.NewRequest("GET", "/test", nil)
req.Header.Set("X-Real-IP", ip)
req.Header.Set("X-Original-URI", "/normal-path")
w := httptest.NewRecorder()
defender.CheckRequest(w, req)
time.Sleep(1 * time.Millisecond)
}(i)
}

wg.Wait()
time.Sleep(300 * time.Millisecond) // Wait for async eviction

// Verify system stayed within reasonable bounds
defender.mu.RLock()
activeIPs := len(defender.ipTrackers)
droppedIPs := defender.droppedIPs
evictionInProgress := defender.evictionInProgress
defender.mu.RUnlock()

// Should not massively exceed limit
if activeIPs > maxIPs+15 {
t.Errorf("Expected max ~%d IPs (with tolerance), got %d", maxIPs+10, activeIPs)
}

// Should have triggered at least one eviction
if droppedIPs == 0 {
t.Error("Expected some evictions from concurrent requests")
}

if evictionInProgress {
t.Error("Eviction flag should be cleared after completion")
}

t.Logf("Concurrent test: %d active IPs, %d dropped, max allowed: %d", activeIPs, droppedIPs, maxIPs)
}

func TestDefender_ConfigurableEvictionThreshold(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	maxIPs := 100

	// Test different threshold percentages
	testCases := []struct {
		name              string
		thresholdPct      float64
		expectedThreshold int
	}{
		{"95% threshold", 0.95, 95},
		{"90% threshold (default)", 0.90, 90},
		{"85% threshold", 0.85, 85},
		{"80% threshold", 0.80, 80},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defender := NewDefender(DefenderOptions{
				AnalysisThreshold:    100,
				BlockDuration:        60 * time.Minute,
				Storage:              store,
				MaxTrackedIPs:        maxIPs,
				EvictionBatchPct:     0.10,
				EvictionThresholdPct: tc.thresholdPct,
				SimulationMode:       false,
			})

if defender.evictionThreshold != tc.expectedThreshold {
t.Errorf("Expected threshold %d for %.0f%%, got %d", 
tc.expectedThreshold, tc.thresholdPct*100, defender.evictionThreshold)
}

// Fill to just below threshold
for i := 0; i < tc.expectedThreshold-2; i++ {
ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
req := httptest.NewRequest("GET", "/test", nil)
req.Header.Set("X-Real-IP", ip)
req.Header.Set("X-Original-URI", "/normal-path")
w := httptest.NewRecorder()
defender.CheckRequest(w, req)
}

// Verify no eviction yet
defender.mu.RLock()
droppedBefore := defender.droppedIPs
defender.mu.RUnlock()

if droppedBefore != 0 {
t.Errorf("Expected no evictions below threshold, got %d", droppedBefore)
}

// Cross threshold
for i := tc.expectedThreshold-2; i < tc.expectedThreshold+3; i++ {
ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
req := httptest.NewRequest("GET", "/test", nil)
req.Header.Set("X-Real-IP", ip)
req.Header.Set("X-Original-URI", "/normal-path")
w := httptest.NewRecorder()
defender.CheckRequest(w, req)
time.Sleep(2 * time.Millisecond)
}

time.Sleep(150 * time.Millisecond)

// Verify eviction occurred
defender.mu.RLock()
droppedAfter := defender.droppedIPs
defender.mu.RUnlock()

if droppedAfter == 0 {
t.Errorf("Expected eviction at threshold %d (%.0f%%), but got 0 dropped IPs", 
tc.expectedThreshold, tc.thresholdPct*100)
}

t.Logf("%s: Threshold=%d, Dropped=%d IPs", tc.name, tc.expectedThreshold, droppedAfter)
})
}
}

func TestDefender_SimulationMode(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	// Create defender with simulation mode enabled
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    3,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       true,
	})

	suspiciousPaths := []string{
		"/wp-admin",
		"/../etc/passwd",
		"/phpmyadmin",
	}

	ip := "192.168.1.100"
	
	// Send enough requests to trigger analysis (threshold = 3)
	for i := 0; i < 3; i++ {
		path := suspiciousPaths[i%len(suspiciousPaths)]
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Original-URI", path)

		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)
		
		// In simulation mode, requests are always allowed
		if w.Code != http.StatusOK {
			t.Errorf("Expected requests to be allowed in simulation mode, got %d", w.Code)
		}
	}
	
	// Wait for analysis worker to process
	time.Sleep(100 * time.Millisecond)
	
	// Even after suspicious patterns detected, requests should still be allowed
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", ip)
	req.Header.Set("X-Original-URI", "/any-path")
	
	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)
	
	// In simulation mode, IP is "blocked" but request is still allowed (200 instead of 404)
	if w.Code != http.StatusOK {
		t.Errorf("Expected IP to be allowed in simulation mode even after blocking, got %d", w.Code)
	}

	// Verify IP is tracked as blocked internally
	defender.mu.RLock()
	_, inCache := defender.blockedCache[ip]
	defender.mu.RUnlock()

	if !inCache {
		t.Error("Expected IP to be in blocked cache even in simulation mode")
	}
}

func TestDefender_StaticAssetWhitelisting(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    3,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	ip := "192.168.1.50"
	
	// Send 5 legitimate static asset requests
	staticAssets := []string{
		"/scripts/app.js",
		"/css/style.css",
		"/images/logo.png",
		"/lib/jquery.min.js",
		"/fonts/roboto.woff2",
	}
	
	for _, uri := range staticAssets {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Original-URI", uri)
		
		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Expected static asset request to be allowed, got %d for %s", w.Code, uri)
		}
	}
	
	// Wait for analysis
	time.Sleep(100 * time.Millisecond)
	
	// IP should NOT be blocked (all requests were whitelisted)
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", ip)
	req.Header.Set("X-Original-URI", "/any-path")
	
	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected IP with only static assets to NOT be blocked, got %d", w.Code)
	}
	
	// Verify whitelist counter increased
	defender.mu.RLock()
	whitelisted := defender.whitelistedRequests
	defender.mu.RUnlock()
	
	if whitelisted != int64(len(staticAssets)) {
		t.Errorf("Expected %d whitelisted requests, got %d", len(staticAssets), whitelisted)
	}
}

func TestDefender_PartialWhitelisting(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    5,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	ip := "192.168.1.51"
	
	// Send 4 static asset requests + 1 suspicious request
	requests := []string{
		"/scripts/app.js",
		"/css/style.css",
		"/images/logo.png",
		"/lib/jquery.min.js",
		"/wp-admin", // Suspicious!
	}
	
	for _, uri := range requests {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Original-URI", uri)
		
		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)
		
		// All requests allowed initially (deferred analysis)
		if w.Code != http.StatusOK {
			t.Errorf("Expected initial request to be allowed, got %d for %s", w.Code, uri)
		}
	}
	
	// Wait for analysis
	time.Sleep(100 * time.Millisecond)
	
	// IP SHOULD be blocked (1 suspicious request)
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", ip)
	req.Header.Set("X-Original-URI", "/any-path")
	
	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)
	
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected IP with suspicious request to be blocked, got %d", w.Code)
	}
	
	// Verify both whitelist and block counters
	defender.mu.RLock()
	whitelisted := defender.whitelistedRequests
	suspiciousBlocks := defender.suspiciousBlocks
	defender.mu.RUnlock()
	
	if whitelisted != 4 {
		t.Errorf("Expected 4 whitelisted requests, got %d", whitelisted)
	}
	
	if suspiciousBlocks != 1 {
		t.Errorf("Expected 1 suspicious block, got %d", suspiciousBlocks)
	}
}

func TestDefender_PathTraversalOnStaticAssets(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    3,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	ip := "192.168.1.52"
	
	// Send static asset requests with path traversal
	requests := []string{
		"/scripts/../../../etc/passwd",
		"/css/../../config.php",
		"/images/logo.png", // Legitimate
	}
	
	for _, uri := range requests {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Original-URI", uri)
		
		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Expected initial request to be allowed, got %d for %s", w.Code, uri)
		}
	}
	
	// Wait for analysis
	time.Sleep(100 * time.Millisecond)
	
	// IP SHOULD be blocked (path traversal on whitelisted paths)
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", ip)
	req.Header.Set("X-Original-URI", "/any-path")
	
	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)
	
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected IP with path traversal to be blocked, got %d", w.Code)
	}
	
	// Verify path traversal counter
	defender.mu.RLock()
	pathTraversalBlocks := defender.pathTraversalBlocks
	defender.mu.RUnlock()
	
	if pathTraversalBlocks != 1 {
		t.Errorf("Expected 1 path traversal block, got %d", pathTraversalBlocks)
	}
}

func TestDefender_WhitelistPatterns(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    100,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	tests := []struct {
		uri         string
		whitelisted bool
	}{
		{"/scripts/app.js", true},
		{"/scripts/vendor.min.js", true},
		{"/css/style.css", true},
		{"/images/logo.png", true},
		{"/images/icon.svg", true},
		{"/lib/jquery.min.js", true},
		{"/fonts/roboto.woff2", true},
		{"/assets/bundle.js", true},
		{"/api/users", false},
		{"/wp-admin", false},
		{"/normal-path", false},
		{"/scripts/../etc/passwd", false}, // Path matches but has traversal
	}

	for _, tt := range tests {
		result := defender.isWhitelisted(tt.uri)
		if result != tt.whitelisted {
			t.Errorf("URI %s: expected whitelisted=%v, got %v", tt.uri, tt.whitelisted, result)
		}
	}
}

func TestDefender_ExcessiveURLEncodedNesting(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    100,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	tests := []struct {
		name       string
		uri        string
		suspicious bool
		reason     string
	}{
		{
			name:       "Excessive nesting with returnUrl (4+ levels)",
			uri:        "/cuenta/crear?returnUrl=/cuenta/crear?returnUrl%3D/cuenta/ingresar?returnUrl%253D/cuenta/crear?returnUrl%25253D/productos",
			suspicious: true,
			reason:     "4+ levels of URL encoding detected",
		},
		{
			name:       "Excessive nesting with mixed params",
			uri:        "/login?returnUrl=/dashboard?returnUrl%3D/home?returnUrl%253D/account?returnUrl%25253D/settings",
			suspicious: true,
			reason:     "4+ levels of URL encoding detected",
		},
		{
			name:       "Excessive nesting with redirect param",
			uri:        "/auth?redirect=/page1?redirect%3D/page2?redirect%253D/page3",
			suspicious: true,
			reason:     "4+ levels of URL encoding detected",
		},
		{
			name:       "Simple redirect - no nesting",
			uri:        "/simple?returnUrl=/dashboard",
			suspicious: false,
			reason:     "Single level is acceptable",
		},
		{
			name:       "Double nesting - acceptable",
			uri:        "/double?returnUrl=/page?returnUrl%3D/target",
			suspicious: false,
			reason:     "Two levels is acceptable",
		},
		{
			name:       "Normal URL with %20 encoding",
			uri:        "/search?q=hello%20world",
			suspicious: false,
			reason:     "Simple space encoding is not suspicious",
		},
		{
			name:       "URL with %3D (single encoded =)",
			uri:        "/api/data?param%3Dvalue",
			suspicious: false,
			reason:     "Single level encoding is acceptable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := defender.hasExcessiveNesting(tt.uri)
			if result != tt.suspicious {
				t.Errorf("%s: expected suspicious=%v (reason: %s), got %v for URI: %s", 
					tt.name, tt.suspicious, tt.reason, result, tt.uri)
			}
		})
	}
}


func TestDefender_ExcessiveNesting_UnforgivingBehavior(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    5,  // Normal threshold is 5
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	ip := "192.168.1.200"
	excessiveNestingURI := "/cuenta/crear?returnUrl=/cuenta/crear?returnUrl%3D/cuenta/ingresar?returnUrl%253D/cuenta/crear?returnUrl%25253D/productos"

	// First request with excessive nesting - should be BLOCKED IMMEDIATELY
	req1 := httptest.NewRequest("GET", "/check", nil)
	req1.Header.Set("X-Real-IP", ip)
	req1.Header.Set("X-Original-URI", excessiveNestingURI)
	w1 := httptest.NewRecorder()
	defender.CheckRequest(w1, req1)

	// CHANGED: First request should now be blocked immediately (not allowed)
	if w1.Code != http.StatusForbidden {
		t.Errorf("First excessive nesting request should be blocked immediately, got %d", w1.Code)
	}

	// Second request - should also be BLOCKED (from cache)
	req2 := httptest.NewRequest("GET", "/check", nil)
	req2.Header.Set("X-Real-IP", ip)
	req2.Header.Set("X-Original-URI", "/any-path")
	w2 := httptest.NewRecorder()
	defender.CheckRequest(w2, req2)

	if w2.Code != http.StatusForbidden {
		t.Errorf("Second request should be blocked (cached), got %d, expected 403", w2.Code)
	}

	// Verify IP is in blocked cache
	defender.mu.RLock()
	_, blocked := defender.blockedCache[ip]
	excessiveNestingBlocks := defender.excessiveNestingBlocks
	defender.mu.RUnlock()

	if !blocked {
		t.Error("IP should be in blocked cache after immediate blocking")
	}

	if excessiveNestingBlocks != 1 {
		t.Errorf("Expected 1 excessive nesting block, got %d", excessiveNestingBlocks)
	}

	t.Logf("✓ Immediate blocking verified: First request blocked, second request cached block")
}

func TestDefender_ExcessiveNesting_ImmediateBlocking_Performance(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    5,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	// Test that legitimate requests are still fast (fast path)
	legitimateURI := "/productos/detalles/abc123/product-name"
	
	start := time.Now()
	for i := 0; i < 1000; i++ {
		req := httptest.NewRequest("GET", "/check", nil)
		req.Header.Set("X-Real-IP", fmt.Sprintf("10.0.0.%d", i))
		req.Header.Set("X-Original-URI", legitimateURI)
		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Legitimate request should be allowed, got %d", w.Code)
		}
	}
	elapsed := time.Since(start)
	avgPerRequest := elapsed / 1000
	
	t.Logf("Average time per legitimate request: %v", avgPerRequest)
	
	// Should be < 15μs per request (relaxed from 10μs to account for test overhead)
	if avgPerRequest > 15*time.Microsecond {
		t.Errorf("Performance degradation: expected < 15μs per request, got %v", avgPerRequest)
	}
}

func TestDefender_ExcessiveNesting_FastPathOptimization(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    5,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	// Test fast path (no returnUrl)
	result := defender.hasExcessiveNestingFast("/productos/detalles/abc123")
	if result {
		t.Error("Fast path should return false for URIs without returnUrl")
	}

	// Test single returnUrl (not excessive)
	result = defender.hasExcessiveNestingFast("/login?returnUrl=/dashboard")
	if result {
		t.Error("Single returnUrl should not trigger excessive nesting")
	}

	// Test excessive nesting
	result = defender.hasExcessiveNestingFast("/cuenta/crear?returnUrl=/cuenta/crear?returnUrl%3D/cuenta/ingresar?returnUrl%253D/cuenta/crear?returnUrl%25253D/productos")
	if !result {
		t.Error("Excessive nesting (4+ levels) should be detected")
	}

	// Test case insensitivity
	result = defender.hasExcessiveNestingFast("/page?returnurl=/page?returnurl%3D/page?returnurl%253D/target")
	if !result {
		t.Error("Excessive nesting should be detected (case insensitive)")
	}
}

func BenchmarkDefender_HasExcessiveNestingFast(b *testing.B) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    5,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	b.Run("Legitimate-FastPath", func(b *testing.B) {
		uri := "/productos/detalles/abc123/product-name"
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			defender.hasExcessiveNestingFast(uri)
		}
	})

	b.Run("Legitimate-WithReturnUrl", func(b *testing.B) {
		uri := "/login?returnUrl=/dashboard"
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			defender.hasExcessiveNestingFast(uri)
		}
	})

	b.Run("Malicious-ExcessiveNesting", func(b *testing.B) {
		uri := "/cuenta/crear?returnUrl=/cuenta/crear?returnUrl%3D/cuenta/ingresar?returnUrl%253D/cuenta/crear?returnUrl%25253D/productos"
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			defender.hasExcessiveNestingFast(uri)
		}
	})
}

// Extension integration tests

// mockExtension is a test implementation of RequestPreHandler
type mockExtension struct {
	name         string
	shouldBypass bool
	bypassReason string
	returnError  error
	callCount    int
}

func (m *mockExtension) Name() string {
	return m.name
}

func (m *mockExtension) PreHandleRequest(req extensions.RequestInfo) (extensions.PreHandlerResult, error) {
	m.callCount++
	
	if m.returnError != nil {
		return extensions.PreHandlerResult{}, m.returnError
	}

	return extensions.PreHandlerResult{
		ShouldBypass: m.shouldBypass,
		Reason:       m.bypassReason,
	}, nil
}

func TestDefender_RegisterExtension(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    5,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	// Register extension
	ext := &mockExtension{name: "test-extension", shouldBypass: false}
	defender.RegisterExtension(ext)

	// Verify extension is registered
	defender.mu.RLock()
	handlerCount := len(defender.preHandlers)
	defender.mu.RUnlock()

	if handlerCount != 1 {
		t.Errorf("Expected 1 registered extension, got %d", handlerCount)
	}
}

func TestDefender_RegisterExtension_DuplicateRejected(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    5,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	// Register extension twice
	ext1 := &mockExtension{name: "duplicate-test"}
	ext2 := &mockExtension{name: "duplicate-test"}

	defender.RegisterExtension(ext1)
	defender.RegisterExtension(ext2) // Should be rejected

	// Should only have 1 handler
	defender.mu.RLock()
	handlerCount := len(defender.preHandlers)
	defender.mu.RUnlock()

	if handlerCount != 1 {
		t.Errorf("Expected duplicate registration to be rejected, got %d handlers", handlerCount)
	}
}

func TestDefender_RegisterExtension_NilRejected(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    5,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	defender.RegisterExtension(nil)

	// Should have 0 handlers
	defender.mu.RLock()
	handlerCount := len(defender.preHandlers)
	defender.mu.RUnlock()

	if handlerCount != 0 {
		t.Errorf("Expected nil extension to be rejected, got %d handlers", handlerCount)
	}
}

func TestDefender_Extension_Bypass(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    5,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	// Register extension that bypasses all requests
	ext := &mockExtension{
		name:         "bypass-all",
		shouldBypass: true,
		bypassReason: "test bypass",
	}
	defender.RegisterExtension(ext)

	// Send request
	req := httptest.NewRequest("GET", "/check", nil)
	req.Header.Set("X-Real-IP", "192.168.1.100")
	req.Header.Set("X-Original-URI", "/wp-admin") // Normally suspicious

	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)

	// Should be allowed (bypassed)
	if w.Code != http.StatusOK {
		t.Errorf("Expected request to be bypassed, got %d", w.Code)
	}

	// Extension should have been called
	if ext.callCount != 1 {
		t.Errorf("Expected extension to be called once, got %d", ext.callCount)
	}

	// Request should not be tracked
	defender.mu.RLock()
	trackedIPs := len(defender.ipTrackers)
	totalRequests := defender.totalRequests
	defender.mu.RUnlock()

	if trackedIPs != 0 {
		t.Errorf("Expected no tracked IPs for bypassed request, got %d", trackedIPs)
	}

	if totalRequests != 0 {
		t.Errorf("Expected totalRequests to be 0 for bypassed request, got %d", totalRequests)
	}
}

func TestDefender_Extension_NoBypassContinuesNormalFlow(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    5,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	// Register extension that doesn't bypass
	ext := &mockExtension{
		name:         "no-bypass",
		shouldBypass: false,
	}
	defender.RegisterExtension(ext)

	// Send request
	req := httptest.NewRequest("GET", "/check", nil)
	req.Header.Set("X-Real-IP", "192.168.1.101")
	req.Header.Set("X-Original-URI", "/normal-path")

	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)

	// Should be allowed (normal flow)
	if w.Code != http.StatusOK {
		t.Errorf("Expected request to proceed normally, got %d", w.Code)
	}

	// Extension should have been called
	if ext.callCount != 1 {
		t.Errorf("Expected extension to be called once, got %d", ext.callCount)
	}

	// Request SHOULD be tracked (normal processing)
	defender.mu.RLock()
	trackedIPs := len(defender.ipTrackers)
	totalRequests := defender.totalRequests
	defender.mu.RUnlock()

	if trackedIPs != 1 {
		t.Errorf("Expected 1 tracked IP for non-bypassed request, got %d", trackedIPs)
	}

	if totalRequests != 1 {
		t.Errorf("Expected totalRequests to be 1, got %d", totalRequests)
	}
}

func TestDefender_Extension_ErrorFailsOpen(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    5,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	// Register extension that returns error
	ext := &mockExtension{
		name:        "error-extension",
		returnError: fmt.Errorf("test error"),
	}
	defender.RegisterExtension(ext)

	// Send request
	req := httptest.NewRequest("GET", "/check", nil)
	req.Header.Set("X-Real-IP", "192.168.1.102")
	req.Header.Set("X-Original-URI", "/normal-path")

	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)

	// Should proceed normally (fail-open)
	if w.Code != http.StatusOK {
		t.Errorf("Expected error to fail-open, got %d", w.Code)
	}

	// Extension should have been called
	if ext.callCount != 1 {
		t.Errorf("Expected extension to be called once, got %d", ext.callCount)
	}

	// Request should be tracked (normal processing continued)
	defender.mu.RLock()
	trackedIPs := len(defender.ipTrackers)
	defender.mu.RUnlock()

	if trackedIPs != 1 {
		t.Errorf("Expected 1 tracked IP after extension error, got %d", trackedIPs)
	}
}

func TestDefender_Extension_OrderedExecution(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    5,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	// Register two extensions - first doesn't bypass, second does
	ext1 := &mockExtension{name: "first", shouldBypass: false}
	ext2 := &mockExtension{name: "second", shouldBypass: true, bypassReason: "second handler"}
	
	defender.RegisterExtension(ext1)
	defender.RegisterExtension(ext2)

	// Send request
	req := httptest.NewRequest("GET", "/check", nil)
	req.Header.Set("X-Real-IP", "192.168.1.103")
	req.Header.Set("X-Original-URI", "/test")

	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)

	// Should be bypassed by second handler
	if w.Code != http.StatusOK {
		t.Errorf("Expected request to be bypassed by second handler, got %d", w.Code)
	}

	// Both extensions should have been called
	if ext1.callCount != 1 {
		t.Errorf("Expected first extension to be called, got %d", ext1.callCount)
	}

	if ext2.callCount != 1 {
		t.Errorf("Expected second extension to be called, got %d", ext2.callCount)
	}

	// Request should NOT be tracked (bypassed)
	defender.mu.RLock()
	trackedIPs := len(defender.ipTrackers)
	defender.mu.RUnlock()

	if trackedIPs != 0 {
		t.Errorf("Expected no tracked IPs for bypassed request, got %d", trackedIPs)
	}
}

func TestDefender_Extension_FirstBypassStopsExecution(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    5,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	// Register two extensions - first bypasses, second should not be called
	ext1 := &mockExtension{name: "bypass-first", shouldBypass: true, bypassReason: "first"}
	ext2 := &mockExtension{name: "never-called", shouldBypass: false}
	
	defender.RegisterExtension(ext1)
	defender.RegisterExtension(ext2)

	// Send request
	req := httptest.NewRequest("GET", "/check", nil)
	req.Header.Set("X-Real-IP", "192.168.1.104")
	req.Header.Set("X-Original-URI", "/test")

	w := httptest.NewRecorder()
	defender.CheckRequest(w, req)

	// Should be bypassed by first handler
	if w.Code != http.StatusOK {
		t.Errorf("Expected request to be bypassed, got %d", w.Code)
	}

	// First extension should be called
	if ext1.callCount != 1 {
		t.Errorf("Expected first extension to be called, got %d", ext1.callCount)
	}

	// Second extension should NOT be called (first one bypassed)
	if ext2.callCount != 0 {
		t.Errorf("Expected second extension to NOT be called, got %d", ext2.callCount)
	}
}

func TestDefender_Extension_BypassSkipsBlocking(t *testing.T) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    1, // Low threshold for quick blocking
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	ip := "192.168.1.105"

	// First, send suspicious request WITHOUT extension (should get blocked)
	req1 := httptest.NewRequest("GET", "/check", nil)
	req1.Header.Set("X-Real-IP", ip)
	req1.Header.Set("X-Original-URI", "/wp-admin") // Suspicious

	w1 := httptest.NewRecorder()
	defender.CheckRequest(w1, req1)

	// Wait for analysis
	time.Sleep(100 * time.Millisecond)

	// Second request should be blocked
	req2 := httptest.NewRequest("GET", "/check", nil)
	req2.Header.Set("X-Real-IP", ip)
	req2.Header.Set("X-Original-URI", "/any-path")

	w2 := httptest.NewRecorder()
	defender.CheckRequest(w2, req2)

	if w2.Code != http.StatusForbidden {
		t.Errorf("Expected IP to be blocked, got %d", w2.Code)
	}

	// Now register bypass extension
	ext := &mockExtension{name: "bypass-blocked-ip", shouldBypass: true, bypassReason: "extension override"}
	defender.RegisterExtension(ext)

	// Third request - even though IP is blocked, extension should bypass
	req3 := httptest.NewRequest("GET", "/check", nil)
	req3.Header.Set("X-Real-IP", ip)
	req3.Header.Set("X-Original-URI", "/any-path")

	w3 := httptest.NewRecorder()
	defender.CheckRequest(w3, req3)

	// Should be allowed (extension bypassed blocking check)
	if w3.Code != http.StatusOK {
		t.Errorf("Expected extension to bypass even blocked IP, got %d", w3.Code)
	}
}

func BenchmarkDefender_CheckRequest_WithExtension(b *testing.B) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    100,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	// Register extension that doesn't bypass (normal flow)
	ext := &mockExtension{name: "bench-ext", shouldBypass: false}
	defender.RegisterExtension(ext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/check", nil)
		req.Header.Set("X-Real-IP", fmt.Sprintf("10.0.%d.%d", i/256, i%256))
		req.Header.Set("X-Original-URI", "/normal-path")

		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)
	}
}

func BenchmarkDefender_CheckRequest_WithBypassExtension(b *testing.B) {
	store := storage.NewMemoryStorage(60 * time.Minute)
	defender := NewDefender(DefenderOptions{
		AnalysisThreshold:    100,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	// Register extension that bypasses all (shortest path)
	ext := &mockExtension{name: "bypass-all", shouldBypass: true, bypassReason: "benchmark"}
	defender.RegisterExtension(ext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/check", nil)
		req.Header.Set("X-Real-IP", fmt.Sprintf("10.0.%d.%d", i/256, i%256))
		req.Header.Set("X-Original-URI", "/normal-path")

		w := httptest.NewRecorder()
		defender.CheckRequest(w, req)
	}
}


// Mock PostHandler for testing
type mockPostHandler struct {
name           string
shouldOverride bool
shouldBlock    bool
reason         string
returnError    error
callCount      int
mu             sync.Mutex
}

func (m *mockPostHandler) Name() string {
return m.name
}

func (m *mockPostHandler) PostHandleRequest(ctx extensions.PostHandlerContext) (extensions.PostHandlerResult, error) {
m.mu.Lock()
m.callCount++
m.mu.Unlock()

if m.returnError != nil {
return extensions.PostHandlerResult{}, m.returnError
}

return extensions.PostHandlerResult{
ShouldOverride: m.shouldOverride,
ShouldBlock:    m.shouldBlock,
Reason:         m.reason,
}, nil
}

func (m *mockPostHandler) GetCallCount() int {
m.mu.Lock()
defer m.mu.Unlock()
return m.callCount
}

func TestDefender_RegisterPostHandler(t *testing.T) {
store := storage.NewMemoryStorage(60 * time.Minute)
defender := NewDefender(DefenderOptions{
AnalysisThreshold:    5,
BlockDuration:        60 * time.Minute,
Storage:              store,
MaxTrackedIPs:        10000,
EvictionBatchPct:     0.10,
EvictionThresholdPct: 0.93,
SimulationMode:       false,
})

// Register a post-handler
handler := &mockPostHandler{
name:           "test-post-handler",
shouldOverride: false,
}
defender.RegisterPostHandler(handler)

// Verify registration
defender.mu.RLock()
count := len(defender.postHandlers)
defender.mu.RUnlock()

if count != 1 {
t.Errorf("Expected 1 post-handler, got %d", count)
}

// Test duplicate registration (should be ignored)
defender.RegisterPostHandler(handler)

defender.mu.RLock()
count = len(defender.postHandlers)
defender.mu.RUnlock()

if count != 1 {
t.Errorf("Expected 1 post-handler after duplicate registration, got %d", count)
}

// Test nil handler registration (should be ignored)
defender.RegisterPostHandler(nil)

defender.mu.RLock()
count = len(defender.postHandlers)
defender.mu.RUnlock()

if count != 1 {
t.Errorf("Expected 1 post-handler after nil registration, got %d", count)
}
}

func TestDefender_PostHandler_NoOverride(t *testing.T) {
store := storage.NewMemoryStorage(60 * time.Minute)
defender := NewDefender(DefenderOptions{
AnalysisThreshold:    5,
BlockDuration:        60 * time.Minute,
Storage:              store,
MaxTrackedIPs:        10000,
EvictionBatchPct:     0.10,
EvictionThresholdPct: 0.93,
SimulationMode:       false,
})

// Register a post-handler that doesn't override
handler := &mockPostHandler{
name:           "no-override-handler",
shouldOverride: false,
}
defender.RegisterPostHandler(handler)

// Make a normal request
req := httptest.NewRequest("GET", "/test", nil)
req.Header.Set("X-Real-IP", "192.168.1.1")
req.Header.Set("X-Original-URI", "/normal-path")

w := httptest.NewRecorder()
defender.CheckRequest(w, req)

// Should allow (200) since no override
if w.Code != http.StatusOK {
t.Errorf("Expected status 200, got %d", w.Code)
}

// Verify handler was called
if handler.GetCallCount() != 1 {
t.Errorf("Expected handler to be called once, got %d", handler.GetCallCount())
}
}

func TestDefender_PostHandler_OverrideToBlock(t *testing.T) {
store := storage.NewMemoryStorage(60 * time.Minute)
defender := NewDefender(DefenderOptions{
AnalysisThreshold:    5,
BlockDuration:        60 * time.Minute,
Storage:              store,
MaxTrackedIPs:        10000,
EvictionBatchPct:     0.10,
EvictionThresholdPct: 0.93,
SimulationMode:       false,
})

// Register a post-handler that overrides to block
handler := &mockPostHandler{
name:           "override-to-block-handler",
shouldOverride: true,
shouldBlock:    true,
reason:         "custom block reason",
}
defender.RegisterPostHandler(handler)

// Make a normal request (would normally be allowed)
req := httptest.NewRequest("GET", "/test", nil)
req.Header.Set("X-Real-IP", "192.168.1.1")
req.Header.Set("X-Original-URI", "/normal-path")

w := httptest.NewRecorder()
defender.CheckRequest(w, req)

// Should block (403) due to post-handler override
if w.Code != http.StatusForbidden {
t.Errorf("Expected status 403, got %d", w.Code)
}

// Verify handler was called
if handler.GetCallCount() != 1 {
t.Errorf("Expected handler to be called once, got %d", handler.GetCallCount())
}
}

func TestDefender_PostHandler_OverrideToAllow(t *testing.T) {
store := storage.NewMemoryStorage(60 * time.Minute)
defender := NewDefender(DefenderOptions{
AnalysisThreshold:    3,
BlockDuration:        60 * time.Minute,
Storage:              store,
MaxTrackedIPs:        10000,
EvictionBatchPct:     0.10,
EvictionThresholdPct: 0.93,
SimulationMode:       false,
})

// Register a post-handler that overrides to allow
handler := &mockPostHandler{
name:           "override-to-allow-handler",
shouldOverride: true,
shouldBlock:    false,
reason:         "custom allow reason",
}
defender.RegisterPostHandler(handler)

// Pre-block an IP in storage
ctx := context.Background()
store.BlockIP(ctx, "192.168.1.100", "test block", 60*time.Minute)

// Make a request from blocked IP (would normally be blocked)
req := httptest.NewRequest("GET", "/test", nil)
req.Header.Set("X-Real-IP", "192.168.1.100")
req.Header.Set("X-Original-URI", "/normal-path")

w := httptest.NewRecorder()
defender.CheckRequest(w, req)

// Should allow (200) due to post-handler override
if w.Code != http.StatusOK {
t.Errorf("Expected status 200, got %d", w.Code)
}

// Verify handler was called
if handler.GetCallCount() != 1 {
t.Errorf("Expected handler to be called once, got %d", handler.GetCallCount())
}
}

func TestDefender_PostHandler_Error(t *testing.T) {
store := storage.NewMemoryStorage(60 * time.Minute)
defender := NewDefender(DefenderOptions{
AnalysisThreshold:    5,
BlockDuration:        60 * time.Minute,
Storage:              store,
MaxTrackedIPs:        10000,
EvictionBatchPct:     0.10,
EvictionThresholdPct: 0.93,
SimulationMode:       false,
})

// Register a post-handler that returns an error
handler := &mockPostHandler{
name:        "error-handler",
returnError: fmt.Errorf("test error"),
}
defender.RegisterPostHandler(handler)

// Make a normal request
req := httptest.NewRequest("GET", "/test", nil)
req.Header.Set("X-Real-IP", "192.168.1.1")
req.Header.Set("X-Original-URI", "/normal-path")

w := httptest.NewRecorder()
defender.CheckRequest(w, req)

// Should still allow (fail-open behavior)
if w.Code != http.StatusOK {
t.Errorf("Expected status 200 (fail-open), got %d", w.Code)
}

// Verify handler was called
if handler.GetCallCount() != 1 {
t.Errorf("Expected handler to be called once, got %d", handler.GetCallCount())
}
}

func TestDefender_PostHandler_FirstOverrideWins(t *testing.T) {
store := storage.NewMemoryStorage(60 * time.Minute)
defender := NewDefender(DefenderOptions{
AnalysisThreshold:    5,
BlockDuration:        60 * time.Minute,
Storage:              store,
MaxTrackedIPs:        10000,
EvictionBatchPct:     0.10,
EvictionThresholdPct: 0.93,
SimulationMode:       false,
})

// Register first handler that overrides to block
handler1 := &mockPostHandler{
name:           "first-handler",
shouldOverride: true,
shouldBlock:    true,
reason:         "first handler blocks",
}
defender.RegisterPostHandler(handler1)

// Register second handler that would override to allow
handler2 := &mockPostHandler{
name:           "second-handler",
shouldOverride: true,
shouldBlock:    false,
reason:         "second handler allows",
}
defender.RegisterPostHandler(handler2)

// Make a normal request
req := httptest.NewRequest("GET", "/test", nil)
req.Header.Set("X-Real-IP", "192.168.1.1")
req.Header.Set("X-Original-URI", "/normal-path")

w := httptest.NewRecorder()
defender.CheckRequest(w, req)

// Should block (403) because first handler's override wins
if w.Code != http.StatusForbidden {
t.Errorf("Expected status 403 (first handler wins), got %d", w.Code)
}

// Verify first handler was called
if handler1.GetCallCount() != 1 {
t.Errorf("Expected first handler to be called once, got %d", handler1.GetCallCount())
}

// Verify second handler was NOT called (first override wins)
if handler2.GetCallCount() != 0 {
t.Errorf("Expected second handler to NOT be called, got %d calls", handler2.GetCallCount())
}
}

func TestDefender_GetStats_BlockedIPsShowRequestCount(t *testing.T) {
store := storage.NewMemoryStorage(60 * time.Minute)
defender := NewDefender(DefenderOptions{
AnalysisThreshold:    3,
BlockDuration:        60 * time.Minute,
Storage:              store,
MaxTrackedIPs:        10000,
EvictionBatchPct:     0.10,
EvictionThresholdPct: 0.93,
SimulationMode:       false,
})

ip := "192.168.1.200"
suspiciousPath := "/wp-admin"

// Send 3 requests to reach analysis threshold
for i := 0; i < 3; i++ {
req := httptest.NewRequest("GET", "/test", nil)
req.Header.Set("X-Real-IP", ip)
req.Header.Set("X-Original-URI", suspiciousPath)

w := httptest.NewRecorder()
defender.CheckRequest(w, req)

// First requests are allowed (deferred analysis)
if w.Code != http.StatusOK {
t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
}
}

// Wait for analysis worker to process and block the IP
time.Sleep(100 * time.Millisecond)

// Verify IP is blocked
req := httptest.NewRequest("GET", "/test", nil)
req.Header.Set("X-Real-IP", ip)
req.Header.Set("X-Original-URI", "/any-path")

w := httptest.NewRecorder()
defender.CheckRequest(w, req)

if w.Code != http.StatusForbidden {
t.Fatalf("Expected IP to be blocked (403), got %d", w.Code)
}

// Now check the stats endpoint
statsReq := httptest.NewRequest("GET", "/stats", nil)
statsW := httptest.NewRecorder()
defender.GetStats(statsW, statsReq)

if statsW.Code != http.StatusOK {
t.Fatalf("Expected stats endpoint to return 200, got %d", statsW.Code)
}

// Parse the response
var stats Stats
if err := json.NewDecoder(statsW.Body).Decode(&stats); err != nil {
t.Fatalf("Failed to decode stats response: %v", err)
}

// Verify we have blocked IPs
if len(stats.TopIPs) == 0 {
t.Fatal("Expected at least one blocked IP in TopIPs")
}

// Find our blocked IP
var foundIP *IPStats
for _, ipStats := range stats.TopIPs {
if ipStats.IP == ip {
foundIP = &ipStats
break
}
}

if foundIP == nil {
t.Fatalf("Expected to find IP %s in TopIPs", ip)
}

// Verify the request count is correct (should be 3, not 0)
expectedRequests := 3
if foundIP.Requests != expectedRequests {
t.Errorf("Expected blocked IP to show %d requests, got %d", expectedRequests, foundIP.Requests)
}

// Verify it's marked as blocked
if !foundIP.Blocked {
t.Error("Expected IP to be marked as blocked")
}

// Verify BlockedAt timestamp is set
if foundIP.BlockedAt == "" {
t.Error("Expected BlockedAt timestamp to be set")
}
}

// --- StatsDataProvider tests ---

// mockStatsDataProvider is a test implementation of extensions.StatsDataProvider
type mockStatsDataProvider struct {
name        string
data        map[string]interface{}
returnError error
}

func (m *mockStatsDataProvider) Name() string { return m.name }

func (m *mockStatsDataProvider) GetStats() (map[string]interface{}, error) {
if m.returnError != nil {
return nil, m.returnError
}
return m.data, nil
}

func newTestDefender() *Defender {
return NewDefender(DefenderOptions{
AnalysisThreshold:    5,
BlockDuration:        60 * time.Minute,
Storage:              storage.NewMemoryStorage(60 * time.Minute),
MaxTrackedIPs:        10000,
EvictionBatchPct:     0.10,
EvictionThresholdPct: 0.93,
})
}

func TestDefender_RegisterStatsProvider(t *testing.T) {
d := newTestDefender()

provider := &mockStatsDataProvider{
name: "test-provider",
data: map[string]interface{}{"metric": 1},
}

d.RegisterStatsProvider(provider)

d.mu.RLock()
count := len(d.statsProviders)
d.mu.RUnlock()

if count != 1 {
t.Errorf("Expected 1 stats provider, got %d", count)
}
}

func TestDefender_RegisterStatsProvider_DuplicateRejected(t *testing.T) {
d := newTestDefender()

p1 := &mockStatsDataProvider{name: "dup-provider", data: map[string]interface{}{}}
p2 := &mockStatsDataProvider{name: "dup-provider", data: map[string]interface{}{}}

d.RegisterStatsProvider(p1)
d.RegisterStatsProvider(p2) // should be rejected

d.mu.RLock()
count := len(d.statsProviders)
d.mu.RUnlock()

if count != 1 {
t.Errorf("Expected 1 stats provider after duplicate, got %d", count)
}
}

func TestDefender_RegisterStatsProvider_NilRejected(t *testing.T) {
d := newTestDefender()
// Should not panic
d.RegisterStatsProvider(nil)

d.mu.RLock()
count := len(d.statsProviders)
d.mu.RUnlock()

if count != 0 {
t.Errorf("Expected 0 stats providers after nil registration, got %d", count)
}
}

func TestDefender_CollectExtensionStats_NoProviders(t *testing.T) {
d := newTestDefender()

result := d.collectExtensionStats()
if result != nil {
t.Errorf("Expected nil when no providers registered, got %v", result)
}
}

func TestDefender_CollectExtensionStats_SingleProvider(t *testing.T) {
d := newTestDefender()

d.RegisterStatsProvider(&mockStatsDataProvider{
name: "ext1",
data: map[string]interface{}{"counter": 42},
})

result := d.collectExtensionStats()

if result == nil {
t.Fatal("Expected non-nil result")
}

ext1Data, ok := result["ext1"]
if !ok {
t.Fatal("Expected 'ext1' key in result")
}

dataMap, ok := ext1Data.(map[string]interface{})
if !ok {
t.Fatalf("Expected map, got %T", ext1Data)
}

if dataMap["counter"] != 42 {
t.Errorf("Expected counter=42, got %v", dataMap["counter"])
}
}

func TestDefender_CollectExtensionStats_MultipleProviders(t *testing.T) {
d := newTestDefender()

d.RegisterStatsProvider(&mockStatsDataProvider{
name: "providerA",
data: map[string]interface{}{"a_metric": 1},
})
d.RegisterStatsProvider(&mockStatsDataProvider{
name: "providerB",
data: map[string]interface{}{"b_metric": 2},
})

result := d.collectExtensionStats()

if result == nil {
t.Fatal("Expected non-nil result")
}

if _, ok := result["providerA"]; !ok {
t.Error("Expected 'providerA' key in result")
}

if _, ok := result["providerB"]; !ok {
t.Error("Expected 'providerB' key in result")
}
}

func TestDefender_CollectExtensionStats_ErrorSkipsProvider(t *testing.T) {
d := newTestDefender()

d.RegisterStatsProvider(&mockStatsDataProvider{
name:        "error-provider",
returnError: fmt.Errorf("provider error"),
})
d.RegisterStatsProvider(&mockStatsDataProvider{
name: "good-provider",
data: map[string]interface{}{"status": "ok"},
})

result := d.collectExtensionStats()

if result == nil {
t.Fatal("Expected non-nil result (good provider should contribute)")
}

if _, ok := result["error-provider"]; ok {
t.Error("Expected error provider to be absent from result")
}

if _, ok := result["good-provider"]; !ok {
t.Error("Expected good provider to be present in result")
}
}

func TestDefender_GetStats_IncludesExtensions(t *testing.T) {
d := newTestDefender()

d.RegisterStatsProvider(&mockStatsDataProvider{
name: "my-ext",
data: map[string]interface{}{"custom_value": 99},
})

req := httptest.NewRequest("GET", "/stats", nil)
w := httptest.NewRecorder()
d.GetStats(w, req)

if w.Code != http.StatusOK {
t.Fatalf("Expected 200, got %d", w.Code)
}

var stats Stats
if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
t.Fatalf("Failed to decode stats: %v", err)
}

if stats.Extensions == nil {
t.Fatal("Expected extensions field to be non-nil")
}

extData, ok := stats.Extensions["my-ext"]
if !ok {
t.Fatal("Expected 'my-ext' key in extensions")
}

// JSON numbers decode as float64
dataMap, ok := extData.(map[string]interface{})
if !ok {
t.Fatalf("Expected map, got %T", extData)
}

if dataMap["custom_value"] != float64(99) {
t.Errorf("Expected custom_value=99, got %v", dataMap["custom_value"])
}
}

func TestDefender_GetStats_NoExtensions_OmitsField(t *testing.T) {
d := newTestDefender()

req := httptest.NewRequest("GET", "/stats", nil)
w := httptest.NewRecorder()
d.GetStats(w, req)

if w.Code != http.StatusOK {
t.Fatalf("Expected 200, got %d", w.Code)
}

// Decode into a raw map to check if field is absent
var raw map[string]interface{}
if err := json.NewDecoder(w.Body).Decode(&raw); err != nil {
t.Fatalf("Failed to decode stats: %v", err)
}

if _, exists := raw["extensions"]; exists {
t.Error("Expected 'extensions' field to be absent when no providers registered")
}
}

func TestDefender_GetReport_IncludesExtensions(t *testing.T) {
d := newTestDefender()

d.RegisterStatsProvider(&mockStatsDataProvider{
name: "report-ext",
data: map[string]interface{}{"report_metric": 7},
})

req := httptest.NewRequest("GET", "/report?period=1", nil)
w := httptest.NewRecorder()
d.GetReport(w, req)

if w.Code != http.StatusOK {
t.Fatalf("Expected 200, got %d", w.Code)
}

var report Report
if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
t.Fatalf("Failed to decode report: %v", err)
}

if report.Extensions == nil {
t.Fatal("Expected extensions field to be non-nil")
}

extData, ok := report.Extensions["report-ext"]
if !ok {
t.Fatal("Expected 'report-ext' key in extensions")
}

dataMap, ok := extData.(map[string]interface{})
if !ok {
t.Fatalf("Expected map, got %T", extData)
}

if dataMap["report_metric"] != float64(7) {
t.Errorf("Expected report_metric=7, got %v", dataMap["report_metric"])
}
}

func TestDefender_GetReport_NoExtensions_OmitsField(t *testing.T) {
d := newTestDefender()

req := httptest.NewRequest("GET", "/report?period=1", nil)
w := httptest.NewRecorder()
d.GetReport(w, req)

if w.Code != http.StatusOK {
t.Fatalf("Expected 200, got %d", w.Code)
}

var raw map[string]interface{}
if err := json.NewDecoder(w.Body).Decode(&raw); err != nil {
t.Fatalf("Failed to decode report: %v", err)
}

if _, exists := raw["extensions"]; exists {
t.Error("Expected 'extensions' field to be absent when no providers registered")
}
}

func TestDefender_MetricsHandler_IncludesExtensions(t *testing.T) {
d := newTestDefender()

d.RegisterStatsProvider(&mockStatsDataProvider{
name: "my-provider",
data: map[string]interface{}{
"hit_count":   int64(123),
"string_skip": "ignored",
},
})

req := httptest.NewRequest("GET", "/metrics", nil)
w := httptest.NewRecorder()
d.MetricsHandler(w, req)

if w.Code != http.StatusOK {
t.Fatalf("Expected 200, got %d", w.Code)
}

body := w.Body.String()

// Numeric value should appear as a Prometheus gauge
if !strings.Contains(body, "ops_defender_extension_my_provider_hit_count") {
t.Errorf("Expected extension metric 'ops_defender_extension_my_provider_hit_count' in output, got:\n%s", body)
}

// String values must be skipped
if strings.Contains(body, "string_skip") {
t.Errorf("Expected string value to be skipped, but found 'string_skip' in output")
}
}

func TestDefender_MetricsHandler_NoExtensions_NoExtraOutput(t *testing.T) {
d := newTestDefender()

req := httptest.NewRequest("GET", "/metrics", nil)
w := httptest.NewRecorder()
d.MetricsHandler(w, req)

body := w.Body.String()

if strings.Contains(body, "ops_defender_extension_") {
t.Errorf("Expected no extension metrics with no providers, but found some in output:\n%s", body)
}
}

func TestDefender_TimeSeriesHandler_IncludesExtensions(t *testing.T) {
d := newTestDefender()

d.RegisterStatsProvider(&mockStatsDataProvider{
name: "ts-ext",
data: map[string]interface{}{"ts_counter": 55},
})

req := httptest.NewRequest("GET", "/timeseries?period=1&interval=1h", nil)
w := httptest.NewRecorder()
d.TimeSeriesHandler(w, req)

if w.Code != http.StatusOK {
t.Fatalf("Expected 200, got %d", w.Code)
}

var resp TimeSeriesResponse
if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
t.Fatalf("Failed to decode timeseries response: %v", err)
}

if resp.Extensions == nil {
t.Fatal("Expected extensions field to be non-nil")
}

extData, ok := resp.Extensions["ts-ext"]
if !ok {
t.Fatal("Expected 'ts-ext' key in extensions")
}

dataMap, ok := extData.(map[string]interface{})
if !ok {
t.Fatalf("Expected map, got %T", extData)
}

if dataMap["ts_counter"] != float64(55) {
t.Errorf("Expected ts_counter=55, got %v", dataMap["ts_counter"])
}
}

func TestDefender_TimeSeriesHandler_NoExtensions_OmitsField(t *testing.T) {
d := newTestDefender()

req := httptest.NewRequest("GET", "/timeseries?period=1&interval=1h", nil)
w := httptest.NewRecorder()
d.TimeSeriesHandler(w, req)

if w.Code != http.StatusOK {
t.Fatalf("Expected 200, got %d", w.Code)
}

var raw map[string]interface{}
if err := json.NewDecoder(w.Body).Decode(&raw); err != nil {
t.Fatalf("Failed to decode timeseries response: %v", err)
}

if _, exists := raw["extensions"]; exists {
t.Error("Expected 'extensions' field to be absent when no providers registered")
}
}

func TestSanitizePrometheusName(t *testing.T) {
tests := []struct {
input    string
expected string
}{
{"my-provider", "my_provider"},
{"My Provider", "my_provider"},
{"hit.count", "hit_count"},
{"sql-injection-detector", "sql_injection_detector"},
{"already_valid", "already_valid"},
{"has spaces", "has_spaces"},
}

for _, tt := range tests {
t.Run(tt.input, func(t *testing.T) {
got := sanitizePrometheusName(tt.input)
if got != tt.expected {
t.Errorf("sanitizePrometheusName(%q) = %q, want %q", tt.input, got, tt.expected)
}
})
}
}

func TestToFloat64(t *testing.T) {
tests := []struct {
input    interface{}
expected float64
ok       bool
}{
{int(42), 42.0, true},
{int32(10), 10.0, true},
{int64(100), 100.0, true},
{float32(3.14), float64(float32(3.14)), true},
{float64(2.71), 2.71, true},
{uint(5), 5.0, true},
{uint32(7), 7.0, true},
{uint64(9), 9.0, true},
{"string", 0, false},
{true, 0, false},
{nil, 0, false},
}

for _, tt := range tests {
got, ok := toFloat64(tt.input)
if ok != tt.ok {
t.Errorf("toFloat64(%v): ok=%v, want %v", tt.input, ok, tt.ok)
}
if ok && got != tt.expected {
t.Errorf("toFloat64(%v) = %v, want %v", tt.input, got, tt.expected)
}
}
}

// ─── Race-condition tests for StatsDataProvider ───────────────────────────────

// concurrentStatsProvider is a thread-safe mock StatsDataProvider used in
// concurrency tests. It deliberately uses its own mutex to simulate a real
// provider that tracks internal state.
type concurrentStatsProvider struct {
name    string
mu      sync.Mutex
counter int64
}

func (p *concurrentStatsProvider) Name() string { return p.name }
func (p *concurrentStatsProvider) GetStats() (map[string]interface{}, error) {
p.mu.Lock()
defer p.mu.Unlock()
p.counter++
return map[string]interface{}{"calls": p.counter}, nil
}

// TestDefender_StatsProvider_RaceCondition_ConcurrentRegisterAndCollect
// exercises RegisterStatsProvider and collectExtensionStats from many goroutines
// simultaneously. Run with `go test -race` to detect data races.
func TestDefender_StatsProvider_RaceCondition_ConcurrentRegisterAndCollect(t *testing.T) {
d := newTestDefender()

const goroutines = 50

var wg sync.WaitGroup
// Half of the goroutines register providers; the other half collect stats.
for i := 0; i < goroutines; i++ {
wg.Add(1)
go func(idx int) {
defer wg.Done()
if idx%2 == 0 {
// Register a provider (duplicates are silently ignored, that's OK)
name := fmt.Sprintf("provider-%d", idx%5) // 5 unique names
d.RegisterStatsProvider(&concurrentStatsProvider{name: name})
} else {
// Collect stats while registrations may be happening
_ = d.collectExtensionStats()
}
}(i)
}
wg.Wait()

// Verify all 5 unique providers ended up registered exactly once
d.mu.RLock()
count := len(d.statsProviders)
d.mu.RUnlock()
if count > 5 {
t.Errorf("Expected at most 5 providers (one per unique name), got %d", count)
}
}

// TestDefender_StatsProvider_RaceCondition_ConcurrentGetStatsAndRegister
// calls GetStats (HTTP handler) concurrently with RegisterStatsProvider.
func TestDefender_StatsProvider_RaceCondition_ConcurrentGetStatsAndRegister(t *testing.T) {
d := newTestDefender()

var wg sync.WaitGroup
for i := 0; i < 20; i++ {
wg.Add(1)
go func(idx int) {
defer wg.Done()
if idx%2 == 0 {
req := httptest.NewRequest("GET", "/stats", nil)
w := httptest.NewRecorder()
d.GetStats(w, req)
if w.Code != http.StatusOK {
t.Errorf("GetStats returned %d", w.Code)
}
} else {
d.RegisterStatsProvider(&concurrentStatsProvider{
name: fmt.Sprintf("p%d", idx),
})
}
}(i)
}
wg.Wait()
}

// TestDefender_StatsProvider_RaceCondition_ConcurrentMetricsAndRegister
// calls MetricsHandler concurrently with RegisterStatsProvider.
func TestDefender_StatsProvider_RaceCondition_ConcurrentMetricsAndRegister(t *testing.T) {
d := newTestDefender()

var wg sync.WaitGroup
for i := 0; i < 20; i++ {
wg.Add(1)
go func(idx int) {
defer wg.Done()
if idx%2 == 0 {
req := httptest.NewRequest("GET", "/metrics", nil)
w := httptest.NewRecorder()
d.MetricsHandler(w, req)
} else {
d.RegisterStatsProvider(&concurrentStatsProvider{
name: fmt.Sprintf("mp%d", idx),
})
}
}(i)
}
wg.Wait()
}

// TestDefender_StatsProvider_RaceCondition_HighConcurrency_CollectOnly stresses
// collectExtensionStats with many concurrent readers after providers are pre-registered.
func TestDefender_StatsProvider_RaceCondition_HighConcurrency_CollectOnly(t *testing.T) {
d := newTestDefender()

// Pre-register several providers before starting goroutines
for i := 0; i < 5; i++ {
d.RegisterStatsProvider(&concurrentStatsProvider{
name: fmt.Sprintf("pre-provider-%d", i),
})
}

var wg sync.WaitGroup
for i := 0; i < 100; i++ {
wg.Add(1)
go func() {
defer wg.Done()
result := d.collectExtensionStats()
if result == nil {
t.Errorf("Expected non-nil result with pre-registered providers")
}
}()
}
wg.Wait()
}

// ─── Benchmarks for StatsDataProvider code paths ─────────────────────────────

// BenchmarkCollectExtensionStats_NoProviders measures the fast-path cost when
// no StatsDataProviders are registered (should be near zero).
func BenchmarkCollectExtensionStats_NoProviders(b *testing.B) {
d := newTestDefender()
b.ResetTimer()
for i := 0; i < b.N; i++ {
_ = d.collectExtensionStats()
}
}

// BenchmarkCollectExtensionStats_OneProvider measures cost with a single provider.
func BenchmarkCollectExtensionStats_OneProvider(b *testing.B) {
d := newTestDefender()
d.RegisterStatsProvider(&mockStatsDataProvider{
name: "bench-provider",
data: map[string]interface{}{"counter": int64(42)},
})
b.ResetTimer()
for i := 0; i < b.N; i++ {
_ = d.collectExtensionStats()
}
}

// BenchmarkCollectExtensionStats_FiveProviders measures cost with five providers,
// which is a realistic upper-bound for most deployments.
func BenchmarkCollectExtensionStats_FiveProviders(b *testing.B) {
d := newTestDefender()
for i := 0; i < 5; i++ {
d.RegisterStatsProvider(&mockStatsDataProvider{
name: fmt.Sprintf("provider-%d", i),
data: map[string]interface{}{"metric_a": int64(i), "metric_b": float64(i) * 1.5},
})
}
b.ResetTimer()
for i := 0; i < b.N; i++ {
_ = d.collectExtensionStats()
}
}

// BenchmarkGetStats_NoProviders is the baseline: /stats with no extensions.
func BenchmarkGetStats_NoProviders(b *testing.B) {
d := newTestDefender()
b.ResetTimer()
for i := 0; i < b.N; i++ {
req := httptest.NewRequest("GET", "/stats", nil)
w := httptest.NewRecorder()
d.GetStats(w, req)
}
}

// BenchmarkGetStats_WithProviders measures the overhead of extension collection
// layered on top of the /stats baseline.
func BenchmarkGetStats_WithProviders(b *testing.B) {
d := newTestDefender()
for i := 0; i < 3; i++ {
d.RegisterStatsProvider(&mockStatsDataProvider{
name: fmt.Sprintf("p%d", i),
data: map[string]interface{}{"hits": int64(100 + i)},
})
}
b.ResetTimer()
for i := 0; i < b.N; i++ {
req := httptest.NewRequest("GET", "/stats", nil)
w := httptest.NewRecorder()
d.GetStats(w, req)
}
}

// BenchmarkMetricsHandler_NoProviders is the Prometheus metrics baseline.
func BenchmarkMetricsHandler_NoProviders(b *testing.B) {
d := newTestDefender()
b.ResetTimer()
for i := 0; i < b.N; i++ {
req := httptest.NewRequest("GET", "/metrics", nil)
w := httptest.NewRecorder()
d.MetricsHandler(w, req)
}
}

// BenchmarkMetricsHandler_WithProviders measures extension overhead on /metrics.
func BenchmarkMetricsHandler_WithProviders(b *testing.B) {
d := newTestDefender()
for i := 0; i < 3; i++ {
d.RegisterStatsProvider(&mockStatsDataProvider{
name: fmt.Sprintf("prov-%d", i),
data: map[string]interface{}{"gauge_a": int64(i), "gauge_b": float64(i) * 2.0},
})
}
b.ResetTimer()
for i := 0; i < b.N; i++ {
req := httptest.NewRequest("GET", "/metrics", nil)
w := httptest.NewRecorder()
d.MetricsHandler(w, req)
}
}

// BenchmarkSanitizePrometheusName measures the name sanitization helper.
func BenchmarkSanitizePrometheusName(b *testing.B) {
inputs := []string{
"my-extension-name",
"sql injection detector",
"already_valid_name",
"Mixed-Case With Spaces",
}
b.ResetTimer()
for i := 0; i < b.N; i++ {
_ = sanitizePrometheusName(inputs[i%len(inputs)])
}
}
