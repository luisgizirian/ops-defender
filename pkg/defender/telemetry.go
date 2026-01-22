package defender

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// AppInsightsTelemetry handles Azure Application Insights integration
type AppInsightsTelemetry struct {
	mu                 sync.RWMutex
	enabled            bool
	instrumentationKey string
	endpoint           string
	client             *http.Client
	batchSize          int
	flushInterval      time.Duration
	eventQueue         chan TelemetryEvent
	stopChan           chan struct{}
}

// TelemetryEvent represents an event to send to Application Insights
type TelemetryEvent struct {
	Name       string
	Properties map[string]string
	Metrics    map[string]float64
	Timestamp  time.Time
}

// AppInsightsEnvelope is the envelope format for Application Insights
type AppInsightsEnvelope struct {
	Name string                 `json:"name"`
	Time string                 `json:"time"`
	IKey string                 `json:"iKey"`
	Data AppInsightsData        `json:"data"`
	Tags map[string]string      `json:"tags,omitempty"`
}

// AppInsightsData contains the actual telemetry data
type AppInsightsData struct {
	BaseType string                 `json:"baseType"`
	BaseData AppInsightsBaseData    `json:"baseData"`
}

// AppInsightsBaseData contains event properties and metrics
type AppInsightsBaseData struct {
	Ver        int                    `json:"ver"`
	Name       string                 `json:"name"`
	Properties map[string]string      `json:"properties,omitempty"`
	Measurements map[string]float64   `json:"measurements,omitempty"`
}

// NewAppInsightsTelemetry creates a new Application Insights telemetry handler
func NewAppInsightsTelemetry() *AppInsightsTelemetry {
	instrumentationKey := os.Getenv("APPINSIGHTS_INSTRUMENTATION_KEY")
	
	ai := &AppInsightsTelemetry{
		enabled:            os.Getenv("APPINSIGHTS_ENABLED") == "true",
		instrumentationKey: instrumentationKey,
		endpoint:           getEnv("APPINSIGHTS_ENDPOINT", "https://dc.services.visualstudio.com/v2/track"),
		client:             &http.Client{Timeout: 10 * time.Second},
		batchSize:          10,
		flushInterval:      30 * time.Second,
		eventQueue:         make(chan TelemetryEvent, 100),
		stopChan:           make(chan struct{}),
	}

	if ai.enabled && instrumentationKey == "" {
		log.Printf("Warning: APPINSIGHTS_ENABLED is true but APPINSIGHTS_INSTRUMENTATION_KEY is not set")
		ai.enabled = false
	}

	return ai
}

// Start begins processing telemetry events
func (ai *AppInsightsTelemetry) Start() {
	if !ai.enabled {
		return
	}

	log.Printf("Azure Application Insights telemetry enabled (instrumentation key: %s...)", 
		ai.instrumentationKey[:8])
	
	go ai.processBatches()
}

// Stop stops processing telemetry events
func (ai *AppInsightsTelemetry) Stop() {
	if !ai.enabled {
		return
	}

	close(ai.stopChan)
}

// TrackEvent queues an event for sending to Application Insights
func (ai *AppInsightsTelemetry) TrackEvent(name string, properties map[string]string, metrics map[string]float64) {
	if !ai.enabled {
		return
	}

	event := TelemetryEvent{
		Name:       name,
		Properties: properties,
		Metrics:    metrics,
		Timestamp:  time.Now(),
	}

	select {
	case ai.eventQueue <- event:
	default:
		// Queue full, drop event
		log.Printf("Warning: Telemetry event queue full, dropping event: %s", name)
	}
}

// processBatches processes events in batches
func (ai *AppInsightsTelemetry) processBatches() {
	batch := []TelemetryEvent{}
	ticker := time.NewTicker(ai.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ai.stopChan:
			// Flush remaining events before stopping
			if len(batch) > 0 {
				ai.sendBatch(batch)
			}
			return
		case event := <-ai.eventQueue:
			batch = append(batch, event)
			if len(batch) >= ai.batchSize {
				ai.sendBatch(batch)
				batch = []TelemetryEvent{}
			}
		case <-ticker.C:
			if len(batch) > 0 {
				ai.sendBatch(batch)
				batch = []TelemetryEvent{}
			}
		}
	}
}

// sendBatch sends a batch of events to Application Insights
func (ai *AppInsightsTelemetry) sendBatch(events []TelemetryEvent) {
	if len(events) == 0 {
		return
	}

	envelopes := make([]AppInsightsEnvelope, len(events))
	for i, event := range events {
		envelopes[i] = AppInsightsEnvelope{
			Name: "Microsoft.ApplicationInsights.Event",
			Time: event.Timestamp.UTC().Format(time.RFC3339),
			IKey: ai.instrumentationKey,
			Data: AppInsightsData{
				BaseType: "EventData",
				BaseData: AppInsightsBaseData{
					Ver:          2,
					Name:         event.Name,
					Properties:   event.Properties,
					Measurements: event.Metrics,
				},
			},
			Tags: map[string]string{
				"ai.cloud.role": "ops-defender",
			},
		}
	}

	data, err := json.Marshal(envelopes)
	if err != nil {
		log.Printf("Failed to marshal telemetry batch: %v", err)
		return
	}

	req, err := http.NewRequest("POST", ai.endpoint, bytes.NewBuffer(data))
	if err != nil {
		log.Printf("Failed to create telemetry request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	
	resp, err := ai.client.Do(req)
	if err != nil {
		log.Printf("Failed to send telemetry batch: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Telemetry batch rejected with status: %d", resp.StatusCode)
	} else {
		log.Printf("Sent %d telemetry events to Application Insights", len(events))
	}
}

// TrackBlockEvent tracks an IP block event
func (ai *AppInsightsTelemetry) TrackBlockEvent(ip, reason, uri string, requestCount int) {
	ai.TrackEvent("IPBlocked", map[string]string{
		"ip":     ip,
		"reason": reason,
		"uri":    uri,
	}, map[string]float64{
		"request_count": float64(requestCount),
	})
}

// TrackStats tracks current stats
func (ai *AppInsightsTelemetry) TrackStats(activeIPs, blockedIPs int, totalRequests, blockedRequests int64) {
	ai.TrackEvent("DefenderStats", map[string]string{}, map[string]float64{
		"active_ips":       float64(activeIPs),
		"blocked_ips":      float64(blockedIPs),
		"total_requests":   float64(totalRequests),
		"blocked_requests": float64(blockedRequests),
		"block_rate":       calculateBlockRate(totalRequests, blockedRequests),
	})
}

// calculateBlockRate calculates the percentage of blocked requests
func calculateBlockRate(total, blocked int64) float64 {
	if total == 0 {
		return 0.0
	}
	return (float64(blocked) / float64(total)) * 100.0
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
