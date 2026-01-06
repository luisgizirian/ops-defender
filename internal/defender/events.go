package defender

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// EventStream manages Server-Sent Events (SSE) for real-time monitoring
type EventStream struct {
	mu          sync.RWMutex
	clients     map[chan *StreamEvent]bool
	defender    *Defender
	stopChan    chan struct{}
	broadcasting bool
}

// StreamEvent represents a real-time event
type StreamEvent struct {
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// NewEventStream creates a new event stream
func NewEventStream(defender *Defender) *EventStream {
	return &EventStream{
		clients:  make(map[chan *StreamEvent]bool),
		defender: defender,
		stopChan: make(chan struct{}),
	}
}

// Start begins broadcasting events
func (es *EventStream) Start() {
	es.mu.Lock()
	if es.broadcasting {
		es.mu.Unlock()
		return
	}
	es.broadcasting = true
	es.mu.Unlock()

	go es.broadcastStats()
}

// Stop stops broadcasting events
func (es *EventStream) Stop() {
	es.mu.Lock()
	defer es.mu.Unlock()
	
	if !es.broadcasting {
		return
	}
	
	close(es.stopChan)
	es.broadcasting = false
	
	// Close all client channels
	for clientChan := range es.clients {
		close(clientChan)
	}
	es.clients = make(map[chan *StreamEvent]bool)
}

// broadcastStats periodically sends stats to all connected clients
func (es *EventStream) broadcastStats() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-es.stopChan:
			return
		case <-ticker.C:
			es.sendStatsUpdate()
		}
	}
}

// sendStatsUpdate sends current stats to all clients
func (es *EventStream) sendStatsUpdate() {
	es.defender.mu.RLock()
	activeIPs := len(es.defender.ipTrackers)
	totalRequests := es.defender.totalRequests
	blockedRequests := es.defender.blockedRequests
	droppedIPs := es.defender.droppedIPs
	es.defender.mu.RUnlock()

	ctx := context.Background()
	blockedIPs, err := es.defender.storage.GetBlockedIPs(ctx)
	blockedIPCount := 0
	if err == nil {
		blockedIPCount = len(blockedIPs)
	}

	event := &StreamEvent{
		Type:      "stats_update",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"active_ips":       activeIPs,
			"blocked_ips":      blockedIPCount,
			"total_requests":   totalRequests,
			"blocked_requests": blockedRequests,
			"dropped_ips":      droppedIPs,
		},
	}

	es.broadcast(event)
}

// broadcast sends an event to all connected clients
func (es *EventStream) broadcast(event *StreamEvent) {
	es.mu.RLock()
	defer es.mu.RUnlock()

	for clientChan := range es.clients {
		select {
		case clientChan <- event:
		default:
			// Client is slow or disconnected, skip
		}
	}
}

// BroadcastBlockEvent sends a block event to all clients
func (es *EventStream) BroadcastBlockEvent(ip, reason, uri string) {
	event := &StreamEvent{
		Type:      "ip_blocked",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"ip":     ip,
			"reason": reason,
			"uri":    uri,
		},
	}

	es.broadcast(event)
}

// addClient registers a new SSE client
func (es *EventStream) addClient(clientChan chan *StreamEvent) {
	es.mu.Lock()
	defer es.mu.Unlock()
	es.clients[clientChan] = true
}

// removeClient unregisters an SSE client
func (es *EventStream) removeClient(clientChan chan *StreamEvent) {
	es.mu.Lock()
	defer es.mu.Unlock()
	delete(es.clients, clientChan)
	close(clientChan)
}

// StreamHandler handles SSE connections for real-time events
func (es *EventStream) StreamHandler(w http.ResponseWriter, r *http.Request) {
	// Set headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Create a channel for this client
	clientChan := make(chan *StreamEvent, 10)
	es.addClient(clientChan)
	defer es.removeClient(clientChan)

	// Get the flusher
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Send initial connection event
	initialEvent := &StreamEvent{
		Type:      "connected",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"message": "Connected to Ops Defender event stream",
		},
	}
	es.sendEvent(w, flusher, initialEvent)

	// Listen for client disconnect or events
	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			// Client disconnected
			log.Printf("SSE client disconnected")
			return
		case event, ok := <-clientChan:
			if !ok {
				// Channel closed, stream stopped
				return
			}
			es.sendEvent(w, flusher, event)
		}
	}
}

// sendEvent sends a single SSE event
func (es *EventStream) sendEvent(w http.ResponseWriter, flusher http.Flusher, event *StreamEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("Failed to marshal event: %v", err)
		return
	}

	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()
}
