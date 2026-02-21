package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ops/defender/pkg/defender"
	"github.com/ops/defender/pkg/extensions"
	"github.com/ops/defender/pkg/storage"
)

// ──────────────────────────────────────────────────────────────────────────────
// Example 1: RequestRateTracker
//
// Tracks how many requests have been seen per URI path prefix (e.g. /api, /admin).
// Implements StatsDataProvider so the counters appear in /stats, /report,
// /timeseries, /metrics, and /events without a separate endpoint.
// ──────────────────────────────────────────────────────────────────────────────

// RequestRateTracker counts requests per top-level URI prefix.
type RequestRateTracker struct {
	mu       sync.RWMutex
	counters map[string]int64
}

// NewRequestRateTracker creates a new tracker.
func NewRequestRateTracker() *RequestRateTracker {
	return &RequestRateTracker{
		counters: make(map[string]int64),
	}
}

// Name satisfies StatsDataProvider and RequestPreHandler.
func (t *RequestRateTracker) Name() string { return "request-rate-tracker" }

// PreHandleRequest is called on every request. We record the URI prefix and
// let all requests pass through (ShouldBypass=false).
func (t *RequestRateTracker) PreHandleRequest(req extensions.RequestInfo) (extensions.PreHandlerResult, error) {
	prefix := uriPrefix(req.URI)

	t.mu.Lock()
	t.counters[prefix]++
	t.mu.Unlock()

	return extensions.PreHandlerResult{ShouldBypass: false}, nil
}

// GetStats returns the current per-prefix counters. Called by the system
// whenever /stats, /report, /timeseries, /metrics, or /events are served.
func (t *RequestRateTracker) GetStats() (map[string]interface{}, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make(map[string]interface{}, len(t.counters))
	for prefix, count := range t.counters {
		result[prefix] = count
	}
	return result, nil
}

// uriPrefix extracts the first path segment, e.g. "/api/users" → "api".
func uriPrefix(uri string) string {
	trimmed := strings.TrimPrefix(uri, "/")
	if idx := strings.Index(trimmed, "/"); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	if trimmed == "" {
		return "root"
	}
	return trimmed
}

// ──────────────────────────────────────────────────────────────────────────────
// Example 2: BlockedIPAuditStats
//
// Keeps a simple audit counter: how many times a block decision was *observed*
// by a PostHandler. Implements both StatsDataProvider and RequestPostHandler.
// ──────────────────────────────────────────────────────────────────────────────

// BlockedIPAuditStats counts post-handler invocations where a block occurred.
type BlockedIPAuditStats struct {
	totalBlocks   int64 // atomic
	totalAllows   int64 // atomic
	lastBlockedIP string
	mu            sync.RWMutex
}

// NewBlockedIPAuditStats creates a new audit stats tracker.
func NewBlockedIPAuditStats() *BlockedIPAuditStats {
	return &BlockedIPAuditStats{}
}

// Name satisfies both StatsDataProvider and RequestPostHandler.
func (a *BlockedIPAuditStats) Name() string { return "audit-stats" }

// PostHandleRequest is called after the core system has made a block decision.
// We record it for stats, but never override the core decision.
func (a *BlockedIPAuditStats) PostHandleRequest(ctx extensions.PostHandlerContext) (extensions.PostHandlerResult, error) {
	if ctx.WasBlocked {
		atomic.AddInt64(&a.totalBlocks, 1)
		a.mu.Lock()
		a.lastBlockedIP = ctx.Request.IP
		a.mu.Unlock()
	} else {
		atomic.AddInt64(&a.totalAllows, 1)
	}
	// Never override core decision — only observe.
	return extensions.PostHandlerResult{ShouldOverride: false}, nil
}

// GetStats returns the current audit counters.
func (a *BlockedIPAuditStats) GetStats() (map[string]interface{}, error) {
	a.mu.RLock()
	lastIP := a.lastBlockedIP
	a.mu.RUnlock()

	return map[string]interface{}{
		"total_blocks":    atomic.LoadInt64(&a.totalBlocks),
		"total_allows":    atomic.LoadInt64(&a.totalAllows),
		"last_blocked_ip": lastIP,
	}, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// main
// ──────────────────────────────────────────────────────────────────────────────

func main() {
	// Memory storage (no Redis needed for this demo)
	store := storage.NewMemoryStorage(60 * time.Minute)

	d := defender.NewDefender(defender.DefenderOptions{
		AnalysisThreshold:    5,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	// ── Extension 1: RequestRateTracker ──────────────────────────────────────
	// It is both a PreHandler (to observe every request) AND a StatsDataProvider
	// (to expose the counters). Register it for both roles.
	rateTracker := NewRequestRateTracker()
	d.RegisterExtension(rateTracker)     // PreHandler role
	d.RegisterStatsProvider(rateTracker) // StatsDataProvider role

	log.Println("Registered: request-rate-tracker (PreHandler + StatsDataProvider)")

	// ── Extension 2: BlockedIPAuditStats ────────────────────────────────────
	// It is both a PostHandler (to observe block decisions) AND a StatsDataProvider.
	auditStats := NewBlockedIPAuditStats()
	d.RegisterPostHandler(auditStats)   // PostHandler role
	d.RegisterStatsProvider(auditStats) // StatsDataProvider role

	log.Println("Registered: audit-stats (PostHandler + StatsDataProvider)")

	// ── HTTP endpoints ────────────────────────────────────────────────────────
	http.HandleFunc("/check", d.CheckRequest)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK\n")
	})
	http.HandleFunc("/stats", d.GetStats)
	http.HandleFunc("/report", d.GetReport)
	http.HandleFunc("/metrics", d.MetricsHandler)
	http.HandleFunc("/timeseries", d.TimeSeriesHandler)

	// ── Start event stream ────────────────────────────────────────────────────
	eventStream := defender.NewEventStream(d)
	eventStream.Start()
	d.SetEventStream(eventStream)
	http.HandleFunc("/events", eventStream.StreamHandler)

	port := "8080"
	log.Printf("Starting stats-provider-example on :%s", port)
	log.Println()
	log.Println("── Try it out ──────────────────────────────────────────────────")
	log.Println("Send some requests:")
	log.Println(`  curl -H "X-Real-IP: 10.0.0.1" -H "X-Original-URI: /api/users"   http://localhost:8080/check`)
	log.Println(`  curl -H "X-Real-IP: 10.0.0.2" -H "X-Original-URI: /admin/panel" http://localhost:8080/check`)
	log.Println()
	log.Println("Then query the informational endpoints:")
	log.Println("  curl http://localhost:8080/stats     | jq .extensions")
	log.Println("  curl http://localhost:8080/report    | jq .extensions")
	log.Println(`  curl http://localhost:8080/timeseries | jq .extensions`)
	log.Println("  curl http://localhost:8080/metrics   | grep ops_defender_extension")
	log.Println("  curl -N http://localhost:8080/events  (SSE stream)")
	log.Println("────────────────────────────────────────────────────────────────")

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
