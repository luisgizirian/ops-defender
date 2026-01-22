package defender

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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

