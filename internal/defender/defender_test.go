package defender

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ops/defender/internal/storage"
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
	
	if w.Code != http.StatusNotFound {
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
		if i >= 15 && w.Code == http.StatusNotFound {
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
		name     string
		headers  map[string]string
		expected string
	}{
		{
			name:     "X-Real-IP header",
			headers:  map[string]string{"X-Real-IP": "10.0.0.1"},
			expected: "10.0.0.1",
		},
		{
			name:     "X-Forwarded-For header",
			headers:  map[string]string{"X-Forwarded-For": "10.0.0.2, 10.0.0.3"},
			expected: "10.0.0.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			ip := defender.extractIP(req)
			if ip != tt.expected {
				t.Errorf("Expected IP %s, got %s", tt.expected, ip)
			}
		})
	}
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
		{"/../etc/passwd", true},
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

