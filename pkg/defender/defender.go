package defender

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ops/defender/pkg/extensions"
	"github.com/ops/defender/pkg/storage"
)

const (
	// evictionTimeout is the maximum time to wait for bulk eviction to complete
	// before proceeding with new IP addition to avoid blocking requests
	evictionTimeout = 50 * time.Millisecond
)

type RequestLog struct {
	URI           string
	Timestamp     time.Time
	UserAgent     string
	IsWhitelisted bool
}

type IPTracker struct {
	RequestLogs   []RequestLog
	Blocked       bool
	BlockedAt     time.Time
	AnalysisCount int
}

// DefenderOptions contains configuration options for creating a new Defender
type DefenderOptions struct {
	AnalysisThreshold    int             // Number of requests to collect before analysis
	BlockDuration        time.Duration   // Duration to block suspicious IPs
	Storage              storage.Storage // Redis or memory storage for blocked IPs
	MaxTrackedIPs        int             // Maximum number of IPs to track simultaneously
	EvictionBatchPct     float64         // Percentage of IPs to evict in bulk (0.01-1.0, default 0.10)
	EvictionThresholdPct float64         // Preemptive eviction threshold (0.5-1.0, default 0.93)
	SimulationMode       bool            // When true, log blocks but don't actually block requests
}

type Defender struct {
	mu                       sync.RWMutex
	ipTrackers               map[string]*IPTracker // In-memory for active tracking
	blockedCache             map[string]time.Time  // In-memory cache of blocked IPs (IP -> expiry time)
	storage                  storage.Storage       // Redis or memory for blocked IPs
	analysisThreshold        int
	blockDuration            time.Duration
	suspiciousPatterns       []*regexp.Regexp
	whitelistPatterns        []*regexp.Regexp // Static asset patterns to exclude from analysis
	pathTraversalPatterns    []*regexp.Regexp // Path traversal patterns (checked on all requests)
	excessiveNestingPatterns []*regexp.Regexp // Excessive nesting patterns (immediate block on first occurrence)
	nestingPatterns          []string         // Pre-compiled nesting patterns for fast string matching
	analysisChan             chan string
	totalRequests            int64
	blockedRequests          int64
	whitelistedRequests      int64                          // Counter for whitelisted static asset requests
	pathTraversalBlocks      int64                          // Counter for blocks due to path traversal
	excessiveNestingBlocks   int64                          // Counter for blocks due to excessive URL-encoded nesting
	suspiciousBlocks         int64                          // Counter for blocks due to suspicious patterns
	repeatBlockedRequests    int64                          // Counter for requests from already-blocked IPs (cached blocks)
	droppedAnalysis          int64                          // Counter for analysis requests dropped due to channel full
	analysisWorkerRestarts   int64                          // Counter for analysis worker restarts after panic
	maxTrackedIPs            int                            // Maximum number of IPs to track simultaneously
	droppedIPs               int64                          // Counter for IPs dropped due to memory limits
	evictionBatchPct         float64                        // Percentage of IPs to evict in bulk (default 0.10 = 10%)
	evictionInProgress       bool                           // Flag to prevent concurrent evictions
	evictionThreshold        int                            // Preemptive eviction threshold (e.g., 90% of max)
	simulationMode           bool                           // When true, log blocks but don't actually block requests
	telemetry                *AppInsightsTelemetry           // Azure Application Insights telemetry
	eventStream              *EventStream                    // Real-time event stream
	errorLogger              storage.ErrorLogger             // File-based error logger for critical issues
	preHandlers              []extensions.RequestPreHandler  // Registered extension pre-handlers (invoked before request processing)
	patternAnalyzers         []extensions.PatternAnalyzer    // Registered pattern analyzers (invoked during deferred analysis)
	postHandlers             []extensions.RequestPostHandler // Registered extension post-handlers (invoked after request processing, before response)
	workerStopChan           chan struct{}                   // Channel to signal worker shutdown
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
		droppedAnalysis:    0,
		analysisWorkerRestarts: 0,
		evictionBatchPct:   opts.EvictionBatchPct,
		evictionInProgress: false,
		evictionThreshold:  evictionThreshold,
		simulationMode:     opts.SimulationMode,
		workerStopChan:     make(chan struct{}),
	}

	// Initialize path traversal patterns (checked on ALL requests including whitelisted)
	pathTraversalPatterns := []string{
		`\.\.\/`, // Path traversal forward slash
		`\.\.\\`, // Path traversal backslash
	}

	for _, pattern := range pathTraversalPatterns {
		if re, err := regexp.Compile(`(?i)` + pattern); err == nil {
			d.pathTraversalPatterns = append(d.pathTraversalPatterns, re)
		}
	}

	// Initialize excessive nesting patterns (immediate block on first occurrence)
	excessiveNestingPatterns := []string{
		`[?&](returnUrl|redirect|return|url|next|dest|destination|continue|view|target|redir).*%25[23]`, // Excessive URL-encoded nesting (4+ levels)
	}

	for _, pattern := range excessiveNestingPatterns {
		if re, err := regexp.Compile(`(?i)` + pattern); err == nil {
			d.excessiveNestingPatterns = append(d.excessiveNestingPatterns, re)
		}
	}

	// Pre-compile nesting patterns for fast string matching (used in immediate check)
	d.nestingPatterns = []string{
		"returnUrl%3D",
		"returnUrl%253D",
		"returnUrl%25253D",
		"returnurl%3D",
		"returnurl%253D",
		"returnurl%25253D",
	}

	// Initialize whitelist patterns for static assets
	whitelistPatterns := []string{
		`^/scripts/.*\.(js|css|map)$`,                   // JavaScript, CSS, source maps
		`^/images/.*\.(jpg|jpeg|png|gif|svg|webp|ico)$`, // Images
		`^/lib/.*\.(js|css|map)$`,                       // Library files
		`^/css/.*\.css$`,                                // Stylesheets
		`^/fonts/.*\.(woff|woff2|ttf|eot|otf)$`,         // Fonts
		`^/assets/.*\.(js|css|png|jpg|svg|woff|woff2)$`, // Generic assets
	}

	for _, pattern := range whitelistPatterns {
		if re, err := regexp.Compile(`(?i)` + pattern); err == nil {
			d.whitelistPatterns = append(d.whitelistPatterns, re)
		}
	}

	// Initialize suspicious patterns (checked only on non-whitelisted requests)
	patterns := []string{
		`\/wp-admin`,       // WordPress admin
		`\/wp-login`,       // WordPress login
		`\/phpmyadmin`,     // phpMyAdmin
		`\.php$`,           // PHP files
		`\.env$`,           // Environment files
		`\/\.git`,          // Git directory
		`\/admin`,          // Generic admin
		`eval\(`,           // Code injection
		`<script`,          // XSS attempts
		`UNION.*SELECT`,    // SQL injection
		`;\s*DROP\s+TABLE`, // SQL injection
		`/config`,          // Config files
		`/backup`,          // Backup files
		`[?&](redirect|return|url|next|dest|destination|continue|view|target|redir|r|u)=https?://`, // Open redirect
		`[?&](redirect|return|url|next|dest|destination|continue|view|target|redir|r|u)=//`,        // Protocol-relative redirect
		`[?&](redirect|return|url|next|dest|destination|continue|view|target|redir|r|u)=.*%2f%2f`,  // Encoded // in redirect
	}

	for _, pattern := range patterns {
		if re, err := regexp.Compile(`(?i)` + pattern); err == nil {
			d.suspiciousPatterns = append(d.suspiciousPatterns, re)
		}
	}

	// Start background workers
	go d.analysisWorkerManager()
	go d.cleanupExpired()
	go d.healthMonitor()

	return d
}

// handleBlockedRequest handles the response for a blocked IP
// In simulation mode, logs and returns 200; in normal mode, returns 403
func (d *Defender) handleBlockedRequest(w http.ResponseWriter, ip, uri, source string) {
	if d.simulationMode {
		log.Printf("[SIMULATION] Would block IP %s (blocked in %s), but allowing request: %s", ip, source, uri)
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusForbidden) // Changed from 404 to 403 for Nginx compatibility
	}
}

// handleFinalResponse invokes post-handlers and writes the final HTTP response
// This is the single point where all request processing completes and response is sent
func (d *Defender) handleFinalResponse(w http.ResponseWriter, r *http.Request, ip, uri string, wasBlocked bool, blockReason string, wasBypassedByPreHandler bool) {
	// EXTENSION POINT: Invoke post-handlers before final response
	// Post-handlers can override the core system's decision
	d.mu.RLock()
	postHandlers := d.postHandlers // Copy slice to avoid holding lock during extension execution
	d.mu.RUnlock()

	// Default decision from core system
	shouldBlock := wasBlocked

	if len(postHandlers) > 0 {
		requestInfo := extensions.RequestInfoFromHTTP(r, ip, uri)
		postCtx := extensions.PostHandlerContext{
			Request:                 requestInfo,
			WasBlocked:              wasBlocked,
			BlockReason:             blockReason,
			WasBypassedByPreHandler: wasBypassedByPreHandler,
		}

		for _, handler := range postHandlers {
			result, err := handler.PostHandleRequest(postCtx)
			if err != nil {
				// Log error but continue processing (fail-open for extensions)
				log.Printf("PostHandler '%s' returned error, continuing: %v", handler.Name(), err)
				continue
			}

			if result.ShouldOverride {
				// Extension decided to override - use its decision
				shouldBlock = result.ShouldBlock
				reason := result.Reason
				if reason == "" {
					if shouldBlock {
						reason = "post-handler override: block"
					} else {
						reason = "post-handler override: allow"
					}
				}
				log.Printf("Request decision overridden by post-handler '%s': IP=%s, URI=%s, ShouldBlock=%v, Reason=%s",
					handler.Name(), ip, uri, shouldBlock, reason)

				// First post-handler that overrides wins
				break
			}
		}
	}

	// Write final response based on decision
	if shouldBlock {
		if d.simulationMode {
			log.Printf("[SIMULATION] Would block IP %s, but allowing request: %s", ip, uri)
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
	} else {
		w.WriteHeader(http.StatusOK)
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

	// EXTENSION POINT: Invoke pre-handlers before any processing
	// Extensions can inspect the request and decide to bypass all core logic
	d.mu.RLock()
	preHandlers := d.preHandlers // Copy slice to avoid holding lock during extension execution
	d.mu.RUnlock()

	if len(preHandlers) > 0 {
		requestInfo := extensions.RequestInfoFromHTTP(r, ip, uri)

		for _, handler := range preHandlers {
			result, err := handler.PreHandleRequest(requestInfo)
			if err != nil {
				// Log error but continue processing (fail-open for extensions)
				log.Printf("Extension '%s' returned error, continuing: %v", handler.Name(), err)
				continue
			}

			if result.ShouldBypass {
				// Extension decided to bypass - skip all processing and logging
				reason := result.Reason
				if reason == "" {
					reason = "extension bypass"
				}
				log.Printf("Request bypassed by extension '%s': IP=%s, URI=%s, Reason=%s",
					handler.Name(), ip, uri, reason)

				// Use handleFinalResponse to allow post-handlers to see this bypass decision
				d.handleFinalResponse(w, r, ip, uri, false, "", true)
				return
			}
		}
	}

	// Increment total requests at the very start (before any blocking logic)
	d.mu.Lock()
	d.totalRequests++
	d.mu.Unlock()

	// OPTIMIZATION: Check blockedCache FIRST before any expensive pattern matching
	// This catches repeat requests from already-blocked IPs (~100ns vs ~1150ns for hasExcessiveNestingFast)
	d.mu.RLock()
	if expiresAt, blocked := d.blockedCache[ip]; blocked && time.Now().Before(expiresAt) {
		d.mu.RUnlock()
		d.mu.Lock()
		d.blockedRequests++
		d.repeatBlockedRequests++
		d.mu.Unlock()

		// DEBUG: Log repeat blocks from cached IPs with nesting patterns
		if strings.Contains(strings.ToLower(uri), "returnurl") {
			log.Printf("DEBUG: IP %s already blocked (cache), blocking repeat request: %s", ip, uri)
		}

		d.handleFinalResponse(w, r, ip, uri, true, "IP blocked (cache)", false)
		return
	}
	d.mu.RUnlock()

	// DEBUG: Log URIs with returnUrl to diagnose pattern matching
	if strings.Contains(strings.ToLower(uri), "returnurl") {
		log.Printf("DEBUG: IP=%s, URI=%s, HasNesting=%v", ip, uri, d.hasExcessiveNestingFast(uri))
	}

	// IMMEDIATE CHECK: Block excessive nesting BEFORE logging (unforgiving)
	// This prevents the first malicious request from reaching the backend
	if d.hasExcessiveNestingFast(uri) {
		// ATOMIC CHECK-AND-SET: Use single Lock to prevent race condition
		// This ensures concurrent requests can't all pass the "already blocked?" check
		d.mu.Lock()
		if expiresAt, blocked := d.blockedCache[ip]; blocked && time.Now().Before(expiresAt) {
			// Already blocked - increment counters and return
			d.blockedRequests++
			d.repeatBlockedRequests++
			d.mu.Unlock()

			log.Printf("DEBUG: IP %s already blocked (immediate-nesting), blocking repeat request: %s", ip, uri)
			d.handleFinalResponse(w, r, ip, uri, true, "IP blocked (cache-nesting)", false)
			return
		}

		// First detection - block immediately (still holding lock)
		expiresAt := time.Now().Add(d.blockDuration)
		d.blockedCache[ip] = expiresAt
		d.excessiveNestingBlocks++
		d.blockedRequests++
		d.mu.Unlock()

		// Record in storage (async to avoid blocking response)
		go func() {
			ctx := context.Background()
			reason := "Excessive URL-encoded nesting detected (immediate block)"
			if err := d.storage.BlockIP(ctx, ip, reason, d.blockDuration); err != nil {
				log.Printf("Failed to store blocked IP in storage: %v", err)
			}

			// Record block event for reporting
			event := storage.BlockEvent{
				IP:            ip,
				BlockedAt:     time.Now(),
				Reason:        reason,
				SuspiciousURI: uri,
				RequestCount:  1, // First request
			}
			if err := d.storage.RecordBlockEvent(ctx, event); err != nil {
				log.Printf("Failed to record block event: %v", err)
			}

			// Send telemetry to Application Insights
			if d.telemetry != nil {
				d.telemetry.TrackBlockEvent(ip, reason, uri, 1)
			}

			// Broadcast to real-time event stream
			if d.eventStream != nil {
				d.eventStream.BroadcastBlockEvent(ip, reason, uri)
			}
		}()

		log.Printf("BLOCKED (immediate): IP %s - excessive nesting on first request: %s", ip, uri)
		d.handleFinalResponse(w, r, ip, uri, true, "Excessive URL-encoded nesting detected (immediate block)", false)
		return
	}

	// Fast path: Check if actively tracking this IP
	d.mu.RLock()
	tracker, exists := d.ipTrackers[ip]
	d.mu.RUnlock()

	// Slow path: If not in memory, check Redis (only if IP is unknown)
	if !exists {
		blocked, err := d.storage.IsBlocked(ctx, ip)
		if err != nil {
			// Fail-open: On Redis error, allow request through (don't block)
			log.Printf("WARNING: Redis error checking block status for %s, allowing request: %v", ip, err)
			blocked = false // Explicitly set to false to allow request
		}

		if blocked {
			// Add to cache for next time
			d.mu.Lock()
			d.blockedCache[ip] = time.Now().Add(d.blockDuration)
			d.blockedRequests++
			d.mu.Unlock()

			d.handleFinalResponse(w, r, ip, uri, true, "IP blocked (storage)", false)
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

	// Check if this is a whitelisted static asset request
	isWhitelisted := d.isWhitelisted(uri)
	if isWhitelisted {
		d.whitelistedRequests++
	}

	// Add request to log
	tracker.RequestLogs = append(tracker.RequestLogs, RequestLog{
		URI:           uri,
		Timestamp:     time.Now(),
		UserAgent:     userAgent,
		IsWhitelisted: isWhitelisted,
	})

	requestCount := len(tracker.RequestLogs)
	analysisCount := tracker.AnalysisCount
	// totalRequests is now incremented at the start of CheckRequest()
	d.mu.Unlock()

	// Check for excessive URL-encoded nesting outside critical section (regex matching can be expensive)
	hasExcessiveNesting := d.hasExcessiveNesting(uri)

	// Trigger analysis:
	// - Immediately if excessive nesting detected and we have at least 1 request (first one allowed for analysis)
	// - Or after normal threshold reached for other patterns (asynchronously)
	if (hasExcessiveNesting && requestCount >= 1 && analysisCount == 0) ||
		(requestCount >= d.analysisThreshold && analysisCount == 0) {
		select {
		case d.analysisChan <- ip:
		default:
			// Channel full, increment dropped counter and log warning
			d.mu.Lock()
			d.droppedAnalysis++
			droppedCount := d.droppedAnalysis
			d.mu.Unlock()
			
			// Log warning every 100 dropped requests
			if droppedCount%100 == 1 {
				log.Printf("WARNING: Analysis channel full, dropped analysis for IP %s (total dropped: %d)", ip, droppedCount)
			}
		}
	}

	// Allow request to proceed (non-blocking)
	d.handleFinalResponse(w, r, ip, uri, false, "", false)
}

// analysisWorkerManager manages the analysis worker with automatic restart on panic
func (d *Defender) analysisWorkerManager() {
	for {
		select {
		case <-d.workerStopChan:
			log.Printf("Analysis worker manager stopping")
			return
		default:
			d.runAnalysisWorkerWithRecovery()
		}
	}
}

// runAnalysisWorkerWithRecovery runs the analysis worker with panic recovery
func (d *Defender) runAnalysisWorkerWithRecovery() {
	defer func() {
		if r := recover(); r != nil {
			d.mu.Lock()
			d.analysisWorkerRestarts++
			restartCount := d.analysisWorkerRestarts
			d.mu.Unlock()
			
			// Log critical error
			log.Printf("CRITICAL: Analysis worker panicked and restarting (restart #%d): %v", restartCount, r)
			
			// Log to error logger if available
			if d.errorLogger != nil {
				d.errorLogger.LogCritical("ANALYSIS_WORKER_PANIC", 
					fmt.Sprintf("Analysis worker crashed and restarted (count: %d)", restartCount), 
					fmt.Errorf("%v", r))
			}
			
			// Brief delay before restart to prevent tight loop on persistent errors
			time.Sleep(1 * time.Second)
		}
	}()
	
	d.analysisWorker()
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

	// Analyze request patterns with whitelist separation
	suspicious := false
	var suspiciousURI string
	var reason string
	isPathTraversal := false
	isExcessiveNesting := false

	// Check ALL requests (including whitelisted) for path traversal
	for _, reqLog := range tracker.RequestLogs {
		if d.hasPathTraversal(reqLog.URI) {
			suspicious = true
			suspiciousURI = reqLog.URI
			reason = "Path traversal attempt detected"
			isPathTraversal = true
			break
		}
	}

	// Check for excessive URL-encoded nesting (unforgiving - checked immediately)
	if !suspicious {
		for _, reqLog := range tracker.RequestLogs {
			if d.hasExcessiveNesting(reqLog.URI) {
				suspicious = true
				suspiciousURI = reqLog.URI
				reason = "Excessive URL-encoded nesting detected"
				isExcessiveNesting = true
				break
			}
		}
	}

	// Check only non-whitelisted requests for other suspicious patterns
	if !suspicious {
		for _, reqLog := range tracker.RequestLogs {
			if !reqLog.IsWhitelisted && d.isSuspicious(reqLog.URI) {
				suspicious = true
				suspiciousURI = reqLog.URI
				reason = "Suspicious URL pattern detected"
				break
			}
		}
	}

	// Invoke registered pattern analyzers (if not already suspicious)
	if !suspicious {
		suspicious, suspiciousURI, reason = d.invokePatternAnalyzers(ip, tracker)
	}

	// Check for high request rate in short time (excluding whitelisted static assets)
	if !suspicious && len(tracker.RequestLogs) >= d.analysisThreshold {
		// Count only non-whitelisted requests for rate limiting
		nonWhitelistedCount := 0
		var firstNonWhitelisted, lastNonWhitelisted time.Time

		for _, reqLog := range tracker.RequestLogs {
			if !reqLog.IsWhitelisted {
				if nonWhitelistedCount == 0 {
					firstNonWhitelisted = reqLog.Timestamp
				}
				lastNonWhitelisted = reqLog.Timestamp
				nonWhitelistedCount++
			}
		}

		// Only check rate limit if we have enough non-whitelisted requests
		if nonWhitelistedCount >= d.analysisThreshold {
			duration := lastNonWhitelisted.Sub(firstNonWhitelisted)

			// If threshold requests in less than 10 seconds, suspicious
			if duration < 10*time.Second {
				suspicious = true
				reason = "High request rate"
				log.Printf("High request rate detected for %s: %d non-whitelisted requests in %.2f seconds",
					ip, nonWhitelistedCount, duration.Seconds())
			}
		}
	}

	if suspicious {
		tracker.Blocked = true
		tracker.BlockedAt = time.Now()
		expiresAt := time.Now().Add(d.blockDuration)
		requestCount := len(tracker.RequestLogs)

		// Update block metrics
		if isPathTraversal {
			d.pathTraversalBlocks++
		} else if isExcessiveNesting {
			d.excessiveNestingBlocks++
		} else {
			d.suspiciousBlocks++
		}
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

// invokePatternAnalyzers calls all registered analyzers in priority order
// Returns on first suspicious result or after all complete
// Must be called with mutex held
func (d *Defender) invokePatternAnalyzers(ip string, tracker *IPTracker) (bool, string, string) {
	if len(d.patternAnalyzers) == 0 {
		return false, "", ""
	}

	// Build analysis context (convert internal RequestLog to public type)
	requestLogs := make([]extensions.RequestLog, len(tracker.RequestLogs))
	var firstSeen, lastSeen time.Time

	for i, log := range tracker.RequestLogs {
		requestLogs[i] = extensions.RequestLog{
			URI:           log.URI,
			Timestamp:     log.Timestamp,
			UserAgent:     log.UserAgent,
			IsWhitelisted: log.IsWhitelisted,
			Method:        "", // Method field available for future extension
		}

		if i == 0 {
			firstSeen = log.Timestamp
		}
		lastSeen = log.Timestamp
	}

	ctx := extensions.AnalysisContext{
		IP:           ip,
		RequestLogs:  requestLogs,
		RequestCount: len(requestLogs),
		FirstSeen:    firstSeen,
		LastSeen:     lastSeen,
	}

	// Invoke analyzers in priority order (already sorted during registration)
	for _, analyzer := range d.patternAnalyzers {
		result, err := analyzer.AnalyzePattern(ctx)

		if err != nil {
			// Log error but continue with other analyzers (fail-open)
			log.Printf("Pattern analyzer '%s' returned error, continuing: %v",
				analyzer.Name(), err)
			continue
		}

		if result.IsSuspicious {
			// First suspicious result triggers block
			reason := result.Reason
			if reason == "" {
				reason = fmt.Sprintf("Flagged by %s", analyzer.Name())
			}

			log.Printf("Request pattern flagged by analyzer '%s': IP=%s, Reason=%s, URI=%s, Confidence=%.2f",
				analyzer.Name(), ip, reason, result.SuspiciousURI, result.Confidence)

			return true, result.SuspiciousURI, reason
		}
	}

	return false, "", ""
}

func (d *Defender) isSuspicious(uri string) bool {
	for _, pattern := range d.suspiciousPatterns {
		if pattern.MatchString(uri) {
			return true
		}
	}
	return false
}

// isWhitelisted checks if a URI matches whitelisted static asset patterns
func (d *Defender) isWhitelisted(uri string) bool {
	for _, pattern := range d.whitelistPatterns {
		if pattern.MatchString(uri) {
			return true
		}
	}
	return false
}

// hasPathTraversal checks if a URI contains path traversal attempts
func (d *Defender) hasPathTraversal(uri string) bool {
	for _, pattern := range d.pathTraversalPatterns {
		if pattern.MatchString(uri) {
			return true
		}
	}
	return false
}

// hasExcessiveNesting checks if a URI contains excessive URL-encoded nesting (using regex)
func (d *Defender) hasExcessiveNesting(uri string) bool {
	for _, pattern := range d.excessiveNestingPatterns {
		if pattern.MatchString(uri) {
			return true
		}
	}
	return false
}

// hasExcessiveNestingFast performs optimized string-based check for excessive nesting
// Used in immediate pre-logging check for maximum performance
// Fast path: Early exit if no returnUrl at all (~150ns for 90% of traffic)
func (d *Defender) hasExcessiveNestingFast(uri string) bool {
	// Fast path: Early exit if no returnUrl/returnurl at all
	if !strings.Contains(uri, "returnUrl") && !strings.Contains(uri, "returnurl") {
		return false
	}

	// Count occurrences (case-sensitive is fine, attackers use exact pattern)
	returnURLCount := strings.Count(uri, "returnUrl") + strings.Count(uri, "returnurl")
	if returnURLCount <= 1 {
		return false
	}

	// Check for encoded nesting (pre-compiled patterns)
	for _, pattern := range d.nestingPatterns {
		if strings.Contains(uri, pattern) {
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

	// Fallback to remote address - use net.SplitHostPort for proper IPv4/IPv6 handling
	// RemoteAddr format: "IP:port" for IPv4 or "[IPv6]:port" for IPv6
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}

	// If SplitHostPort fails, return RemoteAddr as-is (edge case)
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

		// Get blocked IPs count from storage (now uses RLock, won't block request path)
		ctx := context.Background()
		blockedIPs, err := d.storage.GetBlockedIPs(ctx)
		blockedIPCount := 0
		if err != nil {
			log.Printf("Cleanup completed: %d active IPs, %d cached blocked IPs", inMemory, cachedBlocked)
		} else {
			blockedIPCount = len(blockedIPs)
			log.Printf("Cleanup completed: %d active IPs, %d cached blocked, %d total in storage",
				inMemory, cachedBlocked, blockedIPCount)
		}

		// Health check and cleanup for storage
		if healthCheckable, ok := d.storage.(storage.HealthCheckable); ok {
			// Clean up expired blocked IPs from storage (uses write lock but separate from reads)
			removedIPs, cleanupErr := healthCheckable.CleanupExpiredBlockedIPs(ctx)
			if cleanupErr != nil {
				if d.errorLogger != nil {
					d.errorLogger.LogError("CLEANUP", "Failed to cleanup expired blocked IPs", cleanupErr)
				}
			} else if removedIPs > 0 {
				log.Printf("Cleaned up %d expired blocked IPs from storage", removedIPs)
			}

			// Monitor block events storage size
			eventsCount, err := healthCheckable.GetBlockEventsCount(ctx)
			if err != nil {
				if d.errorLogger != nil {
					d.errorLogger.LogError("HEALTH_CHECK", "Failed to get block events count", err)
				}
			} else {
				// Determine storage type and appropriate thresholds
				// MemoryStorage self-limits at 900 events, Redis can grow unbounded
				storageType := d.storage.StorageType()
				warnThreshold := int64(5000)
				criticalThreshold := int64(10000)

				if storageType == "memory" {
					// MemoryStorage: adjust thresholds (it self-limits at 900)
					// These should never trigger since storage caps at 900
					warnThreshold = 850
					criticalThreshold = 900
				}

				// Warn if event storage is growing too large
				if eventsCount > criticalThreshold {
					msg := fmt.Sprintf("Block events storage is large: %d events (threshold: %d, type: %s)", eventsCount, criticalThreshold, storageType)
					log.Printf("WARNING: %s", msg)
					if d.errorLogger != nil {
						d.errorLogger.LogCritical("MEMORY_PRESSURE", msg, nil)
					}

					// Attempt manual cleanup of events older than 7 days
					removed, cleanupErr := healthCheckable.CleanupBlockEvents(ctx, 7*24*time.Hour)
					if cleanupErr != nil {
						if d.errorLogger != nil {
							d.errorLogger.LogCritical("CLEANUP_FAILED",
								fmt.Sprintf("Manual cleanup failed, storage size: %d", eventsCount), cleanupErr)
						}
					} else if removed > 0 {
						log.Printf("Manual cleanup: Removed %d old events, remaining: %d", removed, eventsCount-removed)
					}
				} else if eventsCount > warnThreshold {
					// Info-level warning at warn threshold
					log.Printf("INFO: Block events storage size: %d events (monitoring threshold, type: %s)", eventsCount, storageType)
				}
			}
		}
	}
}

// healthMonitor periodically logs health status and monitors for issues
func (d *Defender) healthMonitor() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		d.mu.RLock()
		droppedAnalysis := d.droppedAnalysis
		analysisWorkerRestarts := d.analysisWorkerRestarts
		activeIPs := len(d.ipTrackers)
		maxTrackedIPs := d.maxTrackedIPs
		channelLen := len(d.analysisChan)
		channelCap := cap(d.analysisChan)
		d.mu.RUnlock()

		// Calculate channel usage percentage
		channelUsage := float64(channelLen) / float64(channelCap) * 100

		// Log health status
		log.Printf("HEALTH: Analysis worker restarts=%d, dropped_analysis=%d, channel_usage=%.1f%% (%d/%d), tracked_ips=%d/%d",
			analysisWorkerRestarts, droppedAnalysis, channelUsage, channelLen, channelCap, activeIPs, maxTrackedIPs)

		// Warn on critical conditions
		if analysisWorkerRestarts > 0 {
			log.Printf("WARNING: Analysis worker has restarted %d times - investigate for recurring panics", analysisWorkerRestarts)
			if d.errorLogger != nil {
				d.errorLogger.LogCritical("ANALYSIS_WORKER_HEALTH",
					fmt.Sprintf("Analysis worker has restarted %d times", analysisWorkerRestarts), nil)
			}
		}

		if droppedAnalysis > 0 {
			log.Printf("WARNING: %d analysis requests have been dropped - channel may be full or worker may be slow", droppedAnalysis)
			if d.errorLogger != nil {
				d.errorLogger.LogCritical("DROPPED_ANALYSIS",
					fmt.Sprintf("%d analysis requests dropped", droppedAnalysis), nil)
			}
		}

		if channelUsage > 80 {
			log.Printf("WARNING: Analysis channel is %0.1f%% full (%d/%d) - worker may be falling behind", 
				channelUsage, channelLen, channelCap)
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

// SetErrorLogger sets the error logger for critical issues
func (d *Defender) SetErrorLogger(logger storage.ErrorLogger) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.errorLogger = logger

	// Also set it on storage if it supports health checking
	if healthCheckable, ok := d.storage.(storage.HealthCheckable); ok {
		healthCheckable.SetErrorLogger(logger)
	}
}

// Stop gracefully shuts down the defender's background workers
func (d *Defender) Stop() {
	close(d.workerStopChan)
	// Note: analysisChan is NOT closed to prevent panics on send
	// Workers will exit via workerStopChan signal
}

// RegisterExtension registers a RequestPreHandler extension that will be invoked
// before each request is processed by the core system.
//
// Extensions are invoked in registration order. The first extension that returns
// ShouldBypass=true will cause the request to bypass all core processing.
//
// This method is thread-safe and can be called at any time during the defender's lifecycle.
func (d *Defender) RegisterExtension(handler extensions.RequestPreHandler) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Validate extension
	if handler == nil {
		log.Printf("WARNING: Attempted to register nil extension, ignoring")
		return
	}

	name := handler.Name()
	if name == "" {
		log.Printf("WARNING: Extension has empty name, ignoring registration")
		return
	}

	// Check for duplicate registration
	for _, existing := range d.preHandlers {
		if existing.Name() == name {
			log.Printf("WARNING: Extension '%s' already registered, ignoring duplicate", name)
			return
		}
	}

	d.preHandlers = append(d.preHandlers, handler)
	log.Printf("Registered extension: %s (total extensions: %d)", name, len(d.preHandlers))
}

// RegisterPatternAnalyzer registers a custom pattern analyzer for deferred analysis
//
// Analyzers are invoked during async analysis (after request logging) in priority order.
// They run AFTER built-in checks but BEFORE the final block decision.
//
// Analyzers are sorted by priority (lower Priority() value = runs first).
// The first analyzer returning IsSuspicious=true triggers an IP block.
//
// Thread-safe and can be called during defender lifecycle.
func (d *Defender) RegisterPatternAnalyzer(analyzer extensions.PatternAnalyzer) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Validate analyzer
	if analyzer == nil {
		log.Printf("WARNING: Attempted to register nil PatternAnalyzer, ignoring")
		return
	}

	name := analyzer.Name()
	if name == "" {
		log.Printf("WARNING: PatternAnalyzer has empty name, ignoring registration")
		return
	}

	// Check for duplicate registration
	for _, existing := range d.patternAnalyzers {
		if existing.Name() == name {
			log.Printf("WARNING: PatternAnalyzer '%s' already registered, ignoring duplicate", name)
			return
		}
	}

	// Add to list
	d.patternAnalyzers = append(d.patternAnalyzers, analyzer)

	// Sort by priority (lower = higher priority)
	sort.Slice(d.patternAnalyzers, func(i, j int) bool {
		return d.patternAnalyzers[i].Priority() < d.patternAnalyzers[j].Priority()
	})

	log.Printf("Registered pattern analyzer: %s (priority: %d, total analyzers: %d)",
		name, analyzer.Priority(), len(d.patternAnalyzers))
}

// RegisterPostHandler registers a RequestPostHandler extension that will be invoked
// after request processing is complete but before the HTTP response is sent.
//
// Post-handlers are invoked in registration order. The first post-handler that returns
// ShouldOverride=true will determine the final response (block or allow).
//
// This method is thread-safe and can be called at any time during the defender's lifecycle.
func (d *Defender) RegisterPostHandler(handler extensions.RequestPostHandler) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Validate handler
	if handler == nil {
		log.Printf("WARNING: Attempted to register nil PostHandler, ignoring")
		return
	}

	name := handler.Name()
	if name == "" {
		log.Printf("WARNING: PostHandler has empty name, ignoring registration")
		return
	}

	// Check for duplicate registration
	for _, existing := range d.postHandlers {
		if existing.Name() == name {
			log.Printf("WARNING: PostHandler '%s' already registered, ignoring duplicate", name)
			return
		}
	}

	d.postHandlers = append(d.postHandlers, handler)
	log.Printf("Registered post-handler: %s (total post-handlers: %d)", name, len(d.postHandlers))
}

type Stats struct {
	TotalIPs        int         `json:"total_ips"`
	BlockedIPs      int         `json:"blocked_ips"`
	ActiveIPs       int         `json:"active_ips"`
	TopIPs          []IPStats   `json:"top_ips"`
	MemoryUsage     MemoryStats `json:"memory_usage"`
	TotalRequests   int64       `json:"total_requests"`
	BlockedRequests int64       `json:"blocked_requests"`
}

type MemoryStats struct {
	TrackedIPs             int     `json:"tracked_ips"`
	MaxTrackedIPs          int     `json:"max_tracked_ips"`
	DroppedIPs             int64   `json:"dropped_ips"`
	DroppedAnalysis        int64   `json:"dropped_analysis"`        // Analysis requests dropped due to full channel
	AnalysisWorkerRestarts int64   `json:"analysis_worker_restarts"` // Number of times analysis worker has restarted
	UsagePercent           float64 `json:"usage_percent"`
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
	droppedAnalysis := d.droppedAnalysis
	analysisWorkerRestarts := d.analysisWorkerRestarts
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
			TrackedIPs:             activeIPs,
			MaxTrackedIPs:          maxTrackedIPs,
			DroppedIPs:             droppedIPs,
			DroppedAnalysis:        droppedAnalysis,
			AnalysisWorkerRestarts: analysisWorkerRestarts,
			UsagePercent:           usagePercent,
		},
	}

	// Add blocked IPs from storage
	for _, info := range blockedIPs {
		stats.TopIPs = append(stats.TopIPs, IPStats{
			IP:        info.IP,
			Requests:  0, // Not tracked in storage
			Blocked:   true,
			BlockedAt: info.BlockedAt.Format(time.RFC3339),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

type Report struct {
	GeneratedAt      string               `json:"generated_at"`
	Period           string               `json:"period"`
	TotalRequests    int64                `json:"total_requests"`
	BlockedRequests  int64                `json:"blocked_requests"`
	UniqueIPs        int                  `json:"unique_ips"`
	BlockedIPs       int                  `json:"blocked_ips_count"`
	BlockEvents      []storage.BlockEvent `json:"block_events"`
	TopSuspiciousIPs []IPStats            `json:"top_suspicious_ips"`
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
