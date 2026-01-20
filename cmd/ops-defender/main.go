package main

import (
	"log"
	"net/http"

	"github.com/ops/defender/internal/defender"
	"github.com/ops/defender/internal/logger"
	"github.com/ops/defender/internal/reporter"
	"github.com/ops/defender/internal/storage"
	"github.com/ops/defender/pkg/config"
)

func main() {
	// Load configuration
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

	def := defender.NewDefender(defender.DefenderOptions{
		AnalysisThreshold:    cfg.AnalysisThreshold,
		BlockDuration:        cfg.BlockDuration,
		Storage:              store,
		MaxTrackedIPs:        cfg.MaxTrackedIPs,
		EvictionBatchPct:     cfg.EvictionBatchPct,
		EvictionThresholdPct: cfg.EvictionThresholdPct,
		SimulationMode:       cfg.SimulationMode,
	})

	// Set error logger on defender (will propagate to storage if Redis)
	if errorLogger != nil {
		def.SetErrorLogger(errorLogger)
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

	log.Printf("Ops Defender starting on port %s", cfg.Port)
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

