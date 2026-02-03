package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ops/defender/pkg/defender"
	"github.com/ops/defender/pkg/extensions"
	"github.com/ops/defender/pkg/storage"
)

// EmergencyAllowlist is a PostHandler that allows critical IPs even when blocked
type EmergencyAllowlist struct {
	criticalIPs map[string]bool
}

func NewEmergencyAllowlist(ips []string) *EmergencyAllowlist {
	allowed := make(map[string]bool)
	for _, ip := range ips {
		allowed[ip] = true
	}
	return &EmergencyAllowlist{criticalIPs: allowed}
}

func (e *EmergencyAllowlist) Name() string {
	return "emergency-allowlist"
}

func (e *EmergencyAllowlist) PostHandleRequest(ctx extensions.PostHandlerContext) (extensions.PostHandlerResult, error) {
	// If request was blocked, check if it's from a critical IP
	if ctx.WasBlocked && e.criticalIPs[ctx.Request.IP] {
		return extensions.PostHandlerResult{
			ShouldOverride: true,
			ShouldBlock:    false, // Override: allow instead of block
			Reason:         "critical IP emergency override",
		}, nil
	}

	// Don't override - use core system's decision
	return extensions.PostHandlerResult{ShouldOverride: false}, nil
}

// HealthCheckOverride is a PostHandler that allows health check paths even when IP is blocked
type HealthCheckOverride struct {
	healthPaths map[string]bool
}

func NewHealthCheckOverride(paths []string) *HealthCheckOverride {
	allowed := make(map[string]bool)
	for _, path := range paths {
		allowed[path] = true
	}
	return &HealthCheckOverride{healthPaths: allowed}
}

func (h *HealthCheckOverride) Name() string {
	return "health-check-override"
}

func (h *HealthCheckOverride) PostHandleRequest(ctx extensions.PostHandlerContext) (extensions.PostHandlerResult, error) {
	// Always allow health check endpoints, even if IP is blocked
	if ctx.WasBlocked && h.healthPaths[ctx.Request.URI] {
		return extensions.PostHandlerResult{
			ShouldOverride: true,
			ShouldBlock:    false,
			Reason:         "health check endpoint override",
		}, nil
	}

	return extensions.PostHandlerResult{ShouldOverride: false}, nil
}

func main() {
	// Create memory storage (for demo purposes)
	store := storage.NewMemoryStorage(60 * time.Minute)

	// Create defender with standard configuration
	d := defender.NewDefender(defender.DefenderOptions{
		AnalysisThreshold:    5,
		BlockDuration:        60 * time.Minute,
		Storage:              store,
		MaxTrackedIPs:        10000,
		EvictionBatchPct:     0.10,
		EvictionThresholdPct: 0.93,
		SimulationMode:       false,
	})

	// Register PostHandler #1: Emergency allowlist for critical IPs
	emergencyAllowlist := NewEmergencyAllowlist([]string{
		"10.0.0.1",   // Emergency access IP
		"192.168.1.1", // Admin IP
	})
	d.RegisterPostHandler(emergencyAllowlist)
	log.Printf("Registered emergency allowlist post-handler")

	// Register PostHandler #2: Health check path override
	healthCheckOverride := NewHealthCheckOverride([]string{
		"/health",
		"/readiness",
		"/liveness",
	})
	d.RegisterPostHandler(healthCheckOverride)
	log.Printf("Registered health check override post-handler")

	// Set up HTTP handlers
	http.HandleFunc("/check", d.CheckRequest)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK\n")
	})

	// Start server
	port := "8080"
	log.Printf("Starting ops-defender with PostHandler examples on port %s", port)
	log.Printf("PostHandlers registered:")
	log.Printf("  1. emergency-allowlist - Allows critical IPs: 10.0.0.1, 192.168.1.1")
	log.Printf("  2. health-check-override - Allows paths: /health, /readiness, /liveness")
	log.Printf("\nExample usage:")
	log.Printf("  curl -H 'X-Real-IP: 10.0.0.1' -H 'X-Original-URI: /api/test' http://localhost:8080/check")
	log.Printf("  curl -H 'X-Real-IP: 192.168.1.100' -H 'X-Original-URI: /health' http://localhost:8080/check")

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
