package main

import (
	"log"
	"net/http"
	"os"

	"github.com/ops/defender/pkg/config"
	"github.com/ops/defender/pkg/defender"
	"github.com/ops/defender/pkg/logger"
	"github.com/ops/defender/pkg/reporter"
	"github.com/ops/defender/pkg/storage"
)

func main() {
	// Load core configuration
	cfg := config.LoadConfig()

	// Initialize error logger for persistent error tracking
	errorLogger, err := logger.InitErrorLogger("")
	if err != nil {
		log.Printf("WARNING: Failed to initialize error logger: %v", err)
		log.Println("Continuing without persistent error logging")
	} else {
		defer errorLogger.Close()
		log.Printf("Error logging enabled: %s", errorLogger.GetFilePath())
	}

	// Initialize storage (Redis or Memory)
	store := storage.InitStorage(cfg.RedisURL, cfg.BlockDuration)

	// Create defender instance
	def := defender.NewDefender(defender.DefenderOptions{
		AnalysisThreshold:    cfg.AnalysisThreshold,
		BlockDuration:        cfg.BlockDuration,
		Storage:              store,
		MaxTrackedIPs:        cfg.MaxTrackedIPs,
		EvictionBatchPct:     cfg.EvictionBatchPct,
		EvictionThresholdPct: cfg.EvictionThresholdPct,
		SimulationMode:       cfg.SimulationMode,
	})

	// Set error logger on defender
	if errorLogger != nil {
		def.SetErrorLogger(errorLogger)
	}

	// Load and register IP allowlist extension
	allowlistPath := os.Getenv("ALLOWLIST_CONFIG")
	if allowlistPath == "" {
		allowlistPath = "/etc/ops-defender/allowlist.json"
	}

	allowlistCfg, err := LoadAllowlistConfig(allowlistPath)
	if err != nil {
		log.Printf("WARNING: Could not load allowlist config from %s: %v", allowlistPath, err)
		log.Println("Continuing without IP allowlist extension")
	} else {
		allowlist := NewAllowlistExtension(allowlistCfg.AllowedIPs)
		def.RegisterExtension(allowlist)
		log.Printf("Registered IP allowlist extension with %d entries", len(allowlistCfg.AllowedIPs))
	}

	// Start report scheduler
	scheduler := reporter.NewReportScheduler(def, cfg)
	scheduler.Start()

	// Initialize telemetry (Azure Application Insights)
	telemetry := defender.NewAppInsightsTelemetry()
	telemetry.Start()
	def.SetTelemetry(telemetry)

	// Initialize event stream for real-time monitoring
	eventStream := defender.NewEventStream(def)
	eventStream.Start()
	def.SetEventStream(eventStream)

	// Register HTTP endpoints
	http.HandleFunc("/check", def.CheckRequest)
	http.HandleFunc("/health", healthCheck)
	http.HandleFunc("/stats", def.GetStats)
	http.HandleFunc("/report", def.GetReport)
	http.HandleFunc("/metrics", def.MetricsHandler)
	http.HandleFunc("/timeseries", def.TimeSeriesHandler)
	http.HandleFunc("/events", eventStream.StreamHandler)

	log.Printf("Ops Defender (Staging with IP Allowlist) starting on port %s", cfg.Port)
	log.Printf("Analysis threshold: %d requests, Block duration: %v", cfg.AnalysisThreshold, cfg.BlockDuration)
	log.Printf("Max tracked IPs: %d (preemptive eviction at %.0f%% = %d IPs)",
		cfg.MaxTrackedIPs, cfg.EvictionThresholdPct*100, int(float64(cfg.MaxTrackedIPs)*cfg.EvictionThresholdPct))
	log.Printf("Eviction batch: %.1f%% of tracked IPs", cfg.EvictionBatchPct*100)
	if cfg.SimulationMode {
		log.Printf("Mode: SIMULATION (blocks logged but requests allowed)")
	} else {
		log.Printf("Mode: Deferred analysis (non-blocking)")
	}
	log.Printf("Reporting: Daily (9 AM) and Weekly (Monday 9 AM)")
	log.Printf("Monitoring endpoints: /metrics (Prometheus), /timeseries (JSON), /events (SSE)")

	if err := http.ListenAndServe(":"+cfg.Port, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
