package defender

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/ops/defender/internal/storage"
)

// MetricsHandler provides Prometheus/OpenMetrics format endpoint
func (d *Defender) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	d.mu.RLock()
	activeIPs := len(d.ipTrackers)
	totalRequests := d.totalRequests
	blockedRequests := d.blockedRequests
	whitelistedRequests := d.whitelistedRequests
	pathTraversalBlocks := d.pathTraversalBlocks
	suspiciousBlocks := d.suspiciousBlocks
	maxTrackedIPs := d.maxTrackedIPs
	droppedIPs := d.droppedIPs
	d.mu.RUnlock()

	ctx := context.Background()
	blockedIPs, err := d.storage.GetBlockedIPs(ctx)
	if err != nil {
		// Fail-open: Log error but continue with empty data (don't return 500)
		log.Printf("WARNING: Redis error in MetricsHandler, continuing with partial data: %v", err)
		blockedIPs = []storage.BlockedIPInfo{}
	}

	// Calculate usage percentage
	usagePercent := 0.0
	if maxTrackedIPs > 0 {
		usagePercent = float64(activeIPs) / float64(maxTrackedIPs) * 100
	}

	// Set content type to Prometheus text format
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// Write metrics in Prometheus format
	fmt.Fprintf(w, "# HELP ops_defender_total_requests Total number of requests processed\n")
	fmt.Fprintf(w, "# TYPE ops_defender_total_requests counter\n")
	fmt.Fprintf(w, "ops_defender_total_requests %d\n\n", totalRequests)

	fmt.Fprintf(w, "# HELP ops_defender_blocked_requests Total number of blocked requests\n")
	fmt.Fprintf(w, "# TYPE ops_defender_blocked_requests counter\n")
	fmt.Fprintf(w, "ops_defender_blocked_requests %d\n\n", blockedRequests)

	fmt.Fprintf(w, "# HELP ops_defender_whitelisted_requests Total number of whitelisted static asset requests\n")
	fmt.Fprintf(w, "# TYPE ops_defender_whitelisted_requests counter\n")
	fmt.Fprintf(w, "ops_defender_whitelisted_requests %d\n\n", whitelistedRequests)

	fmt.Fprintf(w, "# HELP ops_defender_path_traversal_blocks Total number of blocks due to path traversal\n")
	fmt.Fprintf(w, "# TYPE ops_defender_path_traversal_blocks counter\n")
	fmt.Fprintf(w, "ops_defender_path_traversal_blocks %d\n\n", pathTraversalBlocks)

	fmt.Fprintf(w, "# HELP ops_defender_suspicious_pattern_blocks Total number of blocks due to suspicious patterns\n")
	fmt.Fprintf(w, "# TYPE ops_defender_suspicious_pattern_blocks counter\n")
	fmt.Fprintf(w, "ops_defender_suspicious_pattern_blocks %d\n\n", suspiciousBlocks)

	fmt.Fprintf(w, "# HELP ops_defender_active_ips Number of actively tracked IPs\n")
	fmt.Fprintf(w, "# TYPE ops_defender_active_ips gauge\n")
	fmt.Fprintf(w, "ops_defender_active_ips %d\n\n", activeIPs)

	fmt.Fprintf(w, "# HELP ops_defender_blocked_ips Number of currently blocked IPs\n")
	fmt.Fprintf(w, "# TYPE ops_defender_blocked_ips gauge\n")
	fmt.Fprintf(w, "ops_defender_blocked_ips %d\n\n", len(blockedIPs))

	fmt.Fprintf(w, "# HELP ops_defender_dropped_ips Total number of IPs dropped due to memory limits\n")
	fmt.Fprintf(w, "# TYPE ops_defender_dropped_ips counter\n")
	fmt.Fprintf(w, "ops_defender_dropped_ips %d\n\n", droppedIPs)

	fmt.Fprintf(w, "# HELP ops_defender_max_tracked_ips Maximum number of IPs that can be tracked\n")
	fmt.Fprintf(w, "# TYPE ops_defender_max_tracked_ips gauge\n")
	fmt.Fprintf(w, "ops_defender_max_tracked_ips %d\n\n", maxTrackedIPs)

	fmt.Fprintf(w, "# HELP ops_defender_memory_usage_percent Percentage of memory limit used\n")
	fmt.Fprintf(w, "# TYPE ops_defender_memory_usage_percent gauge\n")
	fmt.Fprintf(w, "ops_defender_memory_usage_percent %.2f\n\n", usagePercent)

	// Block rate metric
	blockRate := 0.0
	if totalRequests > 0 {
		blockRate = float64(blockedRequests) / float64(totalRequests) * 100
	}
	fmt.Fprintf(w, "# HELP ops_defender_block_rate_percent Percentage of requests blocked\n")
	fmt.Fprintf(w, "# TYPE ops_defender_block_rate_percent gauge\n")
	fmt.Fprintf(w, "ops_defender_block_rate_percent %.2f\n\n", blockRate)
}

// TimeSeriesPoint represents a single data point in time series
type TimeSeriesPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// TimeSeriesData represents time series data for a metric
type TimeSeriesData struct {
	Metric     string            `json:"metric"`
	DataPoints []TimeSeriesPoint `json:"data_points"`
}

// TimeSeriesResponse contains multiple time series
type TimeSeriesResponse struct {
	StartTime   time.Time        `json:"start_time"`
	EndTime     time.Time        `json:"end_time"`
	Interval    string           `json:"interval"`
	TimeSeries  []TimeSeriesData `json:"time_series"`
}

// TimeSeriesHandler provides time-series data for dashboards
func (d *Defender) TimeSeriesHandler(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	periodHours := 24
	if period := r.URL.Query().Get("period"); period != "" {
		if h, err := parseIntParam(period); err == nil {
			periodHours = h
		}
	}

	interval := "1h"
	if i := r.URL.Query().Get("interval"); i != "" {
		interval = i
	}

	endTime := time.Now()
	startTime := endTime.Add(-time.Duration(periodHours) * time.Hour)
	ctx := context.Background()

	// Get block events within the time range
	events, err := d.storage.GetRecentBlockEvents(ctx, startTime)
	if err != nil {
		// Fail-open: Log error but continue with empty events (don't return 500)
		log.Printf("WARNING: Redis error in TimeSeriesHandler, continuing with partial data: %v", err)
		events = []storage.BlockEvent{}
	}

	// Create time series buckets
	buckets := createTimeBuckets(startTime, endTime, interval)
	
	// Aggregate events into buckets
	blockEventsTS := aggregateBlockEvents(events, buckets)
	
	// Get current stats for latest data point
	d.mu.RLock()
	totalRequests := d.totalRequests
	blockedRequests := d.blockedRequests
	activeIPs := len(d.ipTrackers)
	d.mu.RUnlock()

	blockedIPs, _ := d.storage.GetBlockedIPs(ctx)

	response := TimeSeriesResponse{
		StartTime: startTime,
		EndTime:   endTime,
		Interval:  interval,
		TimeSeries: []TimeSeriesData{
			blockEventsTS,
			{
				Metric: "total_requests",
				DataPoints: []TimeSeriesPoint{
					{Timestamp: endTime, Value: float64(totalRequests)},
				},
			},
			{
				Metric: "blocked_requests",
				DataPoints: []TimeSeriesPoint{
					{Timestamp: endTime, Value: float64(blockedRequests)},
				},
			},
			{
				Metric: "active_ips",
				DataPoints: []TimeSeriesPoint{
					{Timestamp: endTime, Value: float64(activeIPs)},
				},
			},
			{
				Metric: "blocked_ips",
				DataPoints: []TimeSeriesPoint{
					{Timestamp: endTime, Value: float64(len(blockedIPs))},
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encodeJSON(w, response)
}

// createTimeBuckets creates time buckets for aggregation
func createTimeBuckets(start, end time.Time, interval string) []time.Time {
	buckets := []time.Time{}
	
	var duration time.Duration
	switch interval {
	case "5m":
		duration = 5 * time.Minute
	case "15m":
		duration = 15 * time.Minute
	case "30m":
		duration = 30 * time.Minute
	case "1h":
		duration = 1 * time.Hour
	case "6h":
		duration = 6 * time.Hour
	case "1d":
		duration = 24 * time.Hour
	default:
		duration = 1 * time.Hour
	}

	current := start
	for current.Before(end) || current.Equal(end) {
		buckets = append(buckets, current)
		current = current.Add(duration)
	}

	return buckets
}

// aggregateBlockEvents aggregates block events into time buckets
func aggregateBlockEvents(events []storage.BlockEvent, buckets []time.Time) TimeSeriesData {
	data := TimeSeriesData{
		Metric:     "block_events",
		DataPoints: []TimeSeriesPoint{},
	}

	if len(buckets) == 0 {
		return data
	}

	// Sort events by time
	sort.Slice(events, func(i, j int) bool {
		return events[i].BlockedAt.Before(events[j].BlockedAt)
	})

	// Count events in each bucket
	for i := 0; i < len(buckets); i++ {
		bucketStart := buckets[i]
		var bucketEnd time.Time
		if i < len(buckets)-1 {
			bucketEnd = buckets[i+1]
		} else {
			bucketEnd = time.Now()
		}

		count := 0
		for _, event := range events {
			if (event.BlockedAt.Equal(bucketStart) || event.BlockedAt.After(bucketStart)) &&
				event.BlockedAt.Before(bucketEnd) {
				count++
			}
		}

		data.DataPoints = append(data.DataPoints, TimeSeriesPoint{
			Timestamp: bucketStart,
			Value:     float64(count),
		})
	}

	return data
}

// Helper function to parse int parameters
func parseIntParam(s string) (int, error) {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}

// Helper function to encode JSON
func encodeJSON(w http.ResponseWriter, v interface{}) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
