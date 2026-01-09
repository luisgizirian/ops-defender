package defender

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ops/defender/internal/storage"
)

const (
	// evictionTimeout is the maximum time to wait for bulk eviction to complete
	// before proceeding with new IP addition to avoid blocking requests
	evictionTimeout = 50 * time.Millisecond
)

type RequestLog struct {
	URI       string
	Timestamp time.Time
	UserAgent string
}

type IPTracker struct {
	RequestLogs   []RequestLog
	Blocked       bool
	BlockedAt     time.Time
	AnalysisCount int
}

// DefenderOptions contains configuration options for creating a new Defender
type DefenderOptions struct {
	AnalysisThreshold    int           // Number of requests to collect before analysis
	BlockDuration        time.Duration // Duration to block suspicious IPs
	Storage              storage.Storage       // Redis or memory storage for blocked IPs
	MaxTrackedIPs        int           // Maximum number of IPs to track simultaneously
	EvictionBatchPct     float64       // Percentage of IPs to evict in bulk (0.01-1.0, default 0.10)
	EvictionThresholdPct float64       // Preemptive eviction threshold (0.5-1.0, default 0.93)
	SimulationMode       bool          // When true, log blocks but don't actually block requests
}

type Defender struct {
	mu                 sync.RWMutex
	ipTrackers         map[string]*IPTracker  // In-memory for active tracking
	blockedCache       map[string]time.Time   // In-memory cache of blocked IPs (IP -> expiry time)
	storage            storage.Storage                 // Redis or memory for blocked IPs
	analysisThreshold  int
	blockDuration      time.Duration
	suspiciousPatterns []*regexp.Regexp
	analysisChan       chan string
	totalRequests      int64
	blockedRequests    int64
	maxTrackedIPs      int                     // Maximum number of IPs to track simultaneously
	droppedIPs         int64                   // Counter for IPs dropped due to memory limits
	evictionBatchPct   float64                 // Percentage of IPs to evict in bulk (default 0.10 = 10%)
	evictionInProgress bool                    // Flag to prevent concurrent evictions
	evictionThreshold  int                     // Preemptive eviction threshold (e.g., 90% of max)
	simulationMode     bool                    // When true, log blocks but don't actually block requests
	telemetry          *AppInsightsTelemetry   // Azure Application Insights telemetry
	eventStream        *EventStream            // Real-time event stream
}

func NewDefender(opts DefenderOptions) *Defender {
	// Validate eviction batch percentage
	if opts.EvictionBatchPct <= 0 || opts.EvictionBatchPct > 1.0 {
		log.Printf("Invalid eviction batch percentage %.2f, using default 0.10 (10%%)", opts.EvictionBatchPct)
		opts.EvictionBatchPct = 0.10
	}
	
	// Validate eviction threshold percentage
	// Default is 0.93 (93%) which provides optimal balance:
	// - Only 7% memory overhead (better than previous 10%)
	// - Sufficient buffer (700 IPs for 10k limit) for concurrent request bursts
	// - Eviction completes (~50ms) well before hitting hard limit
	if opts.EvictionThresholdPct <= 0.5 || opts.EvictionThresholdPct >= 1.0 {
		log.Printf("Invalid eviction threshold percentage %.2f, using optimal default 0.93 (93%%)", opts.EvictionThresholdPct)
		opts.EvictionThresholdPct = 0.93
	}
	
	// Calculate preemptive eviction threshold based on configured percentage
	evictionThreshold := int(float64(opts.MaxTrackedIPs) * opts.EvictionThresholdPct)
	if evictionThreshold < 1 {
		evictionThreshold = 1
	}
	
	d := &Defender{
		ipTrackers:         make(map[string]*IPTracker),
		blockedCache:       make(map[string]time.Time),
		storage:            opts.Storage,
		analysisThreshold:  opts.AnalysisThreshold,
		blockDuration:      opts.BlockDuration,
		analysisChan:       make(chan string, 1000),
		maxTrackedIPs:      opts.MaxTrackedIPs,
		droppedIPs:         0,
		evictionBatchPct:   opts.EvictionBatchPct,
		evictionInProgress: false,
		evictionThreshold:  evictionThreshold,
		simulationMode:     opts.SimulationMode,
	}

	// Initialize suspicious patterns
	patterns := []string{
		`\.\.\/`,                    // Path traversal
		`\/wp-admin`,                // WordPress admin
		`\/wp-login`,                // WordPress login
		`\/phpmyadmin`,              // phpMyAdmin
		`\.php$`,                    // PHP files
		`\.env$`,                    // Environment files
		`\/\.git`,                   // Git directory
		`\/admin`,                   // Generic admin
		`eval\(`,                    // Code injection
		`<script`,                   // XSS attempts
		`UNION.*SELECT`,             // SQL injection
		`;\s*DROP\s+TABLE`,          // SQL injection
		`/config`,                   // Config files
		`/backup`,                   // Backup files
		`[?&](redirect|return|url|next|dest|destination|continue|view|target|redir|r|u)=https?://`,  // Open redirect
		`[?&](redirect|return|url|next|dest|destination|continue|view|target|redir|r|u)=//`,         // Protocol-relative redirect
		`[?&](redirect|return|url|next|dest|destination|continue|view|target|redir|r|u)=.*%2f%2f`,   // Encoded // in redirect
	}

	for _, pattern := range patterns {
		if re, err := regexp.Compile(`(?i)` + pattern); err == nil {
			d.suspiciousPatterns = append(d.suspiciousPatterns, re)
		}
	}

	// Start background workers
	go d.analysisWorker()
	go d.cleanupExpired()

	return d
}

// handleBlockedRequest handles the response for a blocked IP
// In simulation mode, logs and returns 200; in normal mode, returns 404
func (d *Defender) handleBlockedRequest(w http.ResponseWriter, ip, uri, source string) {
	if d.simulationMode {
		log.Printf("[SIMULATION] Would block IP %s (blocked in %s), but allowing request: %s", ip, source, uri)
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *Defender) CheckRequest(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	ip := d.extractIP(r)
	uri := r.Header.Get("X-Original-URI")
	if uri == "" {
		uri = r.URL.Path
	}
	userAgent := r.Header.Get("User-Agent")

	// Fast path 1: Check in-memory blocked cache first (no I/O)
	d.mu.RLock()
	if expiresAt, blocked := d.blockedCache[ip]; blocked {
		// Check if still valid
		if time.Now().Before(expiresAt) {
			d.mu.RUnlock()
			d.mu.Lock()
			d.blockedRequests++
			d.mu.Unlock()
			
			d.handleBlockedRequest(w, ip, uri, "cache")
			return
		}
		// Expired, remove from cache
		d.mu.RUnlock()
		d.mu.Lock()
		delete(d.blockedCache, ip)
		d.mu.Unlock()
		d.mu.RLock()
	}
	d.mu.RUnlock()

	// Fast path 2: Check if actively tracking this IP
	d.mu.RLock()
	tracker, exists := d.ipTrackers[ip]
	d.mu.RUnlock()
	
	// Slow path: If not in memory, check Redis (only if IP is unknown)
	if !exists {
		blocked, err := d.storage.IsBlocked(ctx, ip)
		if err != nil {
			// Fail-open: On Redis error, allow request through (don't block)
			log.Printf("WARNING: Redis error checking block status for %s, allowing request: %v", ip, err)
			blocked = false  // Explicitly set to false to allow request
		}
		
		if blocked {
			// Add to cache for next time
			d.mu.Lock()
			d.blockedCache[ip] = time.Now().Add(d.blockDuration)
			d.blockedRequests++
			d.mu.Unlock()
			
			d.handleBlockedRequest(w, ip, uri, "storage")
			return
		}
	}

	// Log request for deferred analysis (non-blocking)
	d.mu.Lock()
	if !exists {
		currentCount := len(d.ipTrackers)
		
		// Preemptive eviction: trigger at 90% capacity to avoid hitting hard limit
		// Also check if eviction is not already in progress to prevent race condition
		if currentCount >= d.evictionThreshold && !d.evictionInProgress {
			// Mark eviction as in progress to prevent concurrent evictions
			d.evictionInProgress = true
			
			// Trigger bulk eviction asynchronously
			go func() {
				d.evictBulkIPsSync()
				
				// Clear the in-progress flag after eviction completes
				d.mu.Lock()
				d.evictionInProgress = false
				d.mu.Unlock()
			}()
		}
		
		// If we've hit hard limit and eviction is in progress, wait briefly
		if currentCount >= d.maxTrackedIPs {
			if d.evictionInProgress {
				// Release lock and wait for eviction to make room
				d.mu.Unlock()
				time.Sleep(10 * time.Millisecond) // Short wait for eviction
				d.mu.Lock()
				
				// Recheck after waiting
				if len(d.ipTrackers) >= d.maxTrackedIPs {
					// Still at limit - proceed anyway to avoid blocking too long
					log.Printf("Hard limit reached, proceeding with IP addition despite limit")
				}
			} else {
				// No eviction in progress but at limit - this shouldn't happen with preemptive eviction
				// but handle it anyway
				log.Printf("Hard limit reached without active eviction, system may exceed limit temporarily")
			}
		}
		
		tracker = &IPTracker{
			RequestLogs: []RequestLog{},
			Blocked:     false,
		}
		d.ipTrackers[ip] = tracker
	}

	// Add request to log
	tracker.RequestLogs = append(tracker.RequestLogs, RequestLog{
		URI:       uri,
		Timestamp: time.Now(),
		UserAgent: userAgent,
	})

	requestCount := len(tracker.RequestLogs)
	d.totalRequests++
	d.mu.Unlock()

	// Trigger analysis after threshold reached (asynchronously)
	if requestCount >= d.analysisThreshold && tracker.AnalysisCount == 0 {
		select {
		case d.analysisChan <- ip:
		default:
			// Channel full, will be analyzed in next cycle
		}
	}

	// Allow request to proceed (non-blocking)
	w.WriteHeader(http.StatusOK)
}

func (d *Defender) analysisWorker() {
	for ip := range d.analysisChan {
		d.analyzeIP(ip)
	}
}

func (d *Defender) analyzeIP(ip string) {
	d.mu.Lock()
	tracker, exists := d.ipTrackers[ip]
	if !exists || tracker.Blocked {
		d.mu.Unlock()
		return
	}

	// Mark as analyzed
	tracker.AnalysisCount++
	
	// Analyze request patterns
	suspicious := false
	var suspiciousURI string
	var reason string
	
	for _, reqLog := range tracker.RequestLogs {
		if d.isSuspicious(reqLog.URI) {
			suspicious = true
			suspiciousURI = reqLog.URI
			reason = "Suspicious URL pattern detected"
			break
		}
	}

	// Check for high request rate in short time
	if !suspicious && len(tracker.RequestLogs) >= d.analysisThreshold {
		firstReq := tracker.RequestLogs[0].Timestamp
		lastReq := tracker.RequestLogs[len(tracker.RequestLogs)-1].Timestamp
		duration := lastReq.Sub(firstReq)
		
		// If threshold requests in less than 10 seconds, suspicious
		if duration < 10*time.Second {
			suspicious = true
			reason = "High request rate"
			log.Printf("High request rate detected for %s: %d requests in %.2f seconds", 
				ip, len(tracker.RequestLogs), duration.Seconds())
		}
	}

	if suspicious {
		tracker.Blocked = true
		tracker.BlockedAt = time.Now()
		expiresAt := time.Now().Add(d.blockDuration)
		requestCount := len(tracker.RequestLogs)
		d.mu.Unlock()
		
		// Add to in-memory cache immediately
		d.mu.Lock()
		d.blockedCache[ip] = expiresAt
		d.mu.Unlock()
		
		// Store in Redis/persistent storage (async)
		ctx := context.Background()
		if err := d.storage.BlockIP(ctx, ip, reason, d.blockDuration); err != nil {
			log.Printf("Failed to store blocked IP in storage: %v", err)
		}
		
		// Record block event for reporting
		event := storage.BlockEvent{
			IP:            ip,
			BlockedAt:     tracker.BlockedAt,
			Reason:        reason,
			SuspiciousURI: suspiciousURI,
			RequestCount:  requestCount,
		}
		
		if err := d.storage.RecordBlockEvent(ctx, event); err != nil {
			log.Printf("Failed to record block event: %v", err)
		}
		
		// Send telemetry to Application Insights
		if d.telemetry != nil {
			d.telemetry.TrackBlockEvent(ip, reason, suspiciousURI, requestCount)
		}
		
		// Broadcast to real-time event stream
		if d.eventStream != nil {
			d.eventStream.BroadcastBlockEvent(ip, reason, suspiciousURI)
		}
		
		if d.simulationMode {
			log.Printf("[SIMULATION] IP would be blocked: %s (reason: %s, pattern: %s, expires: %v) - but allowing all requests in simulation mode", 
				ip, reason, suspiciousURI, expiresAt.Format(time.RFC3339))
		} else {
			log.Printf("IP marked as suspicious and blocked: %s (reason: %s, pattern: %s, expires: %v)", 
				ip, reason, suspiciousURI, expiresAt.Format(time.RFC3339))
		}
		return
	}
	
	d.mu.Unlock()
}

func (d *Defender) isSuspicious(uri string) bool {
	for _, pattern := range d.suspiciousPatterns {
		if pattern.MatchString(uri) {
			return true
		}
	}
	return false
}

func (d *Defender) extractIP(r *http.Request) string {
	// Check X-Real-IP header (set by Nginx)
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	
	// Fallback to remote address
	parts := strings.Split(r.RemoteAddr, ":")
	if len(parts) > 0 {
		return parts[0]
	}
	
	return r.RemoteAddr
}

// evictBulkIPsSync evicts a batch of oldest IPs (LRU) synchronously
// Must be called without holding the mutex
func (d *Defender) evictBulkIPsSync() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Panic during bulk eviction: %v", r)
		}
	}()
	
	d.mu.Lock()
	defer d.mu.Unlock()
	
	// Calculate how many IPs to evict (default 10% of max)
	evictionCount := int(float64(d.maxTrackedIPs) * d.evictionBatchPct)
	if evictionCount < 1 {
		evictionCount = 1 // Evict at least 1 IP
	}
	
	// Collect all IPs with their last request time for LRU sorting
	type ipWithTime struct {
		ip       string
		lastSeen time.Time
	}
	
	ipsToSort := make([]ipWithTime, 0, len(d.ipTrackers))
	for ip, tracker := range d.ipTrackers {
		if len(tracker.RequestLogs) == 0 {
			// Empty tracker, mark for immediate eviction
			ipsToSort = append(ipsToSort, ipWithTime{ip: ip, lastSeen: time.Time{}})
		} else {
			lastReq := tracker.RequestLogs[len(tracker.RequestLogs)-1].Timestamp
			ipsToSort = append(ipsToSort, ipWithTime{ip: ip, lastSeen: lastReq})
		}
	}
	
	// Sort by last seen time (oldest first)
	sort.Slice(ipsToSort, func(i, j int) bool {
		return ipsToSort[i].lastSeen.Before(ipsToSort[j].lastSeen)
	})
	
	// Limit eviction count to actual number of IPs
	if evictionCount > len(ipsToSort) {
		evictionCount = len(ipsToSort)
	}
	
	// Evict the oldest IPs
	evictedCount := 0
	currentCount := len(d.ipTrackers)
	for i := 0; i < evictionCount; i++ {
		ip := ipsToSort[i].ip
		if _, exists := d.ipTrackers[ip]; exists {
			delete(d.ipTrackers, ip)
			evictedCount++
		}
	}
	
	if evictedCount > 0 {
		d.droppedIPs += int64(evictedCount)
		newCount := len(d.ipTrackers)
		preemptive := currentCount < d.maxTrackedIPs
		log.Printf("Bulk eviction completed: removed %d IPs (%.1f%% of max=%d), count: %d -> %d [%s]", 
			evictedCount, d.evictionBatchPct*100, d.maxTrackedIPs, currentCount, newCount,
			map[bool]string{true: "preemptive", false: "at-limit"}[preemptive])
	}
}

// evictBulkIPs evicts a batch of oldest IPs (LRU) asynchronously
// This is more efficient than evicting one IP at a time
func (d *Defender) evictBulkIPs() {
	go d.evictBulkIPsSync()
}

// evictOldestIP evicts a single IP (kept for backward compatibility, calls bulk eviction with 1 IP)
// DEPRECATED: Use evictBulkIPs instead for better performance
func (d *Defender) evictOldestIP() {
	// Find IP with oldest last request (LRU eviction)
	var oldestIP string
	var oldestTime time.Time
	first := true
	
	for ip, tracker := range d.ipTrackers {
		if len(tracker.RequestLogs) == 0 {
			// Empty tracker, evict immediately
			delete(d.ipTrackers, ip)
			log.Printf("Memory limit reached (%d IPs), evicted IP with empty tracker: %s", 
				d.maxTrackedIPs, ip)
			return
		}
		
		lastReq := tracker.RequestLogs[len(tracker.RequestLogs)-1].Timestamp
		if first || lastReq.Before(oldestTime) {
			oldestTime = lastReq
			oldestIP = ip
			first = false
		}
	}
	
	if oldestIP != "" {
		delete(d.ipTrackers, oldestIP)
		log.Printf("Memory limit reached (%d IPs), evicted oldest IP: %s (last seen: %v)", 
			d.maxTrackedIPs, oldestIP, oldestTime.Format(time.RFC3339))
	}
}

func (d *Defender) cleanupExpired() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		d.mu.Lock()
		now := time.Now()
		
		// Clean up in-memory blocked cache
		for ip, expiresAt := range d.blockedCache {
			if now.After(expiresAt) {
				delete(d.blockedCache, ip)
			}
		}
		
		// Clean up active trackers
		for ip, tracker := range d.ipTrackers {
			// Remove old request logs (keep only last 100)
			if len(tracker.RequestLogs) > 100 {
				tracker.RequestLogs = tracker.RequestLogs[len(tracker.RequestLogs)-100:]
			}
			
			// Remove IPs from memory after 1 hour of inactivity
			if len(tracker.RequestLogs) > 0 {
				lastReq := tracker.RequestLogs[len(tracker.RequestLogs)-1].Timestamp
				if time.Since(lastReq) > 1*time.Hour {
					delete(d.ipTrackers, ip)
				}
			}
		}
		
		inMemory := len(d.ipTrackers)
		cachedBlocked := len(d.blockedCache)
		d.mu.Unlock()
		
		// Get blocked IPs count from storage
		ctx := context.Background()
		blockedIPs, err := d.storage.GetBlockedIPs(ctx)
		if err != nil {
			log.Printf("Cleanup completed: %d active IPs, %d cached blocked IPs", inMemory, cachedBlocked)
		} else {
			log.Printf("Cleanup completed: %d active IPs, %d cached blocked, %d total in storage", 
				inMemory, cachedBlocked, len(blockedIPs))
		}
	}
}

// SetTelemetry sets the telemetry handler
func (d *Defender) SetTelemetry(telemetry *AppInsightsTelemetry) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.telemetry = telemetry
}

// SetEventStream sets the event stream handler
func (d *Defender) SetEventStream(eventStream *EventStream) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.eventStream = eventStream
}

type Stats struct {
	TotalIPs        int       `json:"total_ips"`
	BlockedIPs      int       `json:"blocked_ips"`
	ActiveIPs       int       `json:"active_ips"`
	TopIPs          []IPStats `json:"top_ips"`
	MemoryUsage     MemoryStats `json:"memory_usage"`
	TotalRequests   int64     `json:"total_requests"`
	BlockedRequests int64     `json:"blocked_requests"`
}

type MemoryStats struct {
	TrackedIPs    int   `json:"tracked_ips"`
	MaxTrackedIPs int   `json:"max_tracked_ips"`
	DroppedIPs    int64 `json:"dropped_ips"`
	UsagePercent  float64 `json:"usage_percent"`
}

type IPStats struct {
	IP        string `json:"ip"`
	Requests  int    `json:"requests"`
	Blocked   bool   `json:"blocked"`
	BlockedAt string `json:"blocked_at,omitempty"`
}

func (d *Defender) GetStats(w http.ResponseWriter, r *http.Request) {
	d.mu.RLock()
	activeIPs := len(d.ipTrackers)
	totalRequests := d.totalRequests
	blockedRequests := d.blockedRequests
	maxTrackedIPs := d.maxTrackedIPs
	droppedIPs := d.droppedIPs
	d.mu.RUnlock()

	ctx := context.Background()
	blockedIPs, err := d.storage.GetBlockedIPs(ctx)
	if err != nil {
		log.Printf("Error fetching blocked IPs: %v", err)
		blockedIPs = []storage.BlockedIPInfo{}
	}

	usagePercent := 0.0
	if maxTrackedIPs > 0 {
		usagePercent = float64(activeIPs) / float64(maxTrackedIPs) * 100
	}

	stats := Stats{
		TotalIPs:        activeIPs + len(blockedIPs),
		BlockedIPs:      len(blockedIPs),
		ActiveIPs:       activeIPs,
		TopIPs:          []IPStats{},
		TotalRequests:   totalRequests,
		BlockedRequests: blockedRequests,
		MemoryUsage: MemoryStats{
			TrackedIPs:    activeIPs,
			MaxTrackedIPs: maxTrackedIPs,
			DroppedIPs:    droppedIPs,
			UsagePercent:  usagePercent,
		},
	}

	// Add blocked IPs from storage
	for _, info := range blockedIPs {
		stats.TopIPs = append(stats.TopIPs, IPStats{
			IP:        info.IP,
			Requests:  0,  // Not tracked in storage
			Blocked:   true,
			BlockedAt: info.BlockedAt.Format(time.RFC3339),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

type Report struct {
	GeneratedAt      string       `json:"generated_at"`
	Period           string       `json:"period"`
	TotalRequests    int64        `json:"total_requests"`
	BlockedRequests  int64        `json:"blocked_requests"`
	UniqueIPs        int          `json:"unique_ips"`
	BlockedIPs       int          `json:"blocked_ips_count"`
	BlockEvents      []storage.BlockEvent `json:"block_events"`
	TopSuspiciousIPs []IPStats    `json:"top_suspicious_ips"`
}

func (d *Defender) GenerateReport(periodHours int) Report {
	d.mu.RLock()
	totalRequests := d.totalRequests
	blockedRequests := d.blockedRequests
	activeIPs := len(d.ipTrackers)
	d.mu.RUnlock()

	now := time.Now()
	cutoff := now.Add(-time.Duration(periodHours) * time.Hour)
	ctx := context.Background()

	report := Report{
		GeneratedAt:      now.Format(time.RFC3339),
		Period:           fmt.Sprintf("Last %d hours", periodHours),
		TotalRequests:    totalRequests,
		BlockedRequests:  blockedRequests,
		UniqueIPs:        activeIPs,
		BlockEvents:      []storage.BlockEvent{},
		TopSuspiciousIPs: []IPStats{},
	}

	// Get block events from storage
	events, err := d.storage.GetRecentBlockEvents(ctx, cutoff)
	if err != nil {
		log.Printf("Error fetching block events: %v", err)
	} else {
		report.BlockEvents = events
	}

	// Get blocked IPs from storage
	blockedIPs, err := d.storage.GetBlockedIPs(ctx)
	if err != nil {
		log.Printf("Error fetching blocked IPs: %v", err)
	} else {
		report.BlockedIPs = len(blockedIPs)
		
		// Convert to IPStats
		var ipStats []IPStats
		for _, info := range blockedIPs {
			ipStats = append(ipStats, IPStats{
				IP:        info.IP,
				Requests:  0,
				Blocked:   true,
				BlockedAt: info.BlockedAt.Format(time.RFC3339),
			})
		}

		// Sort by blocked time (most recent first)
		sort.Slice(ipStats, func(i, j int) bool {
			return ipStats[i].BlockedAt > ipStats[j].BlockedAt
		})

		// Take top 10
		if len(ipStats) > 10 {
			report.TopSuspiciousIPs = ipStats[:10]
		} else {
			report.TopSuspiciousIPs = ipStats
		}
	}

	return report
}

func (d *Defender) GetReport(w http.ResponseWriter, r *http.Request) {
	periodHours := 24 // Default to daily
	if period := r.URL.Query().Get("period"); period != "" {
		if h, err := strconv.Atoi(period); err == nil {
			periodHours = h
		}
	}

	report := d.GenerateReport(periodHours)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}
