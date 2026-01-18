package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type BlockEvent struct {
	IP            string
	BlockedAt     time.Time
	Reason        string
	SuspiciousURI string
	RequestCount  int
}

type Storage interface {
	IsBlocked(ctx context.Context, ip string) (bool, error)
	BlockIP(ctx context.Context, ip string, reason string, duration time.Duration, requestCount int) error
	UnblockIP(ctx context.Context, ip string) error
	GetBlockedIPs(ctx context.Context) ([]BlockedIPInfo, error)
	RecordBlockEvent(ctx context.Context, event BlockEvent) error
	GetRecentBlockEvents(ctx context.Context, since time.Time) ([]BlockEvent, error)
	StorageType() string // Returns "redis" or "memory"
}

// HealthCheckable extends Storage with health monitoring capabilities
type HealthCheckable interface {
	Storage
	GetBlockEventsCount(ctx context.Context) (int64, error)
	CleanupBlockEvents(ctx context.Context, olderThan time.Duration) (int64, error)
	SetErrorLogger(logger ErrorLogger)
}

type BlockedIPInfo struct {
	IP           string    `json:"ip"`
	Reason       string    `json:"reason"`
	BlockedAt    time.Time `json:"blocked_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	RequestCount int       `json:"request_count"` // Number of requests before blocking
}

// RedisStorage implements persistent storage with Redis
type RedisStorage struct {
	client        *redis.Client
	blockDuration time.Duration
	errorLogger   ErrorLogger // Interface for error logging
}

// ErrorLogger interface for logging errors
type ErrorLogger interface {
	LogError(category, message string, err error)
	LogCritical(category, message string, err error)
}

func NewRedisStorage(redisURL string, blockDuration time.Duration) (*RedisStorage, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid Redis URL: %w", err)
	}

	client := redis.NewClient(opt)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	log.Printf("Connected to Redis at %s", opt.Addr)

	return &RedisStorage{
		client:        client,
		blockDuration: blockDuration,
	}, nil
}

func (rs *RedisStorage) IsBlocked(ctx context.Context, ip string) (bool, error) {
	key := fmt.Sprintf("blocked:%s", ip)
	exists, err := rs.client.Exists(ctx, key).Result()
	return exists > 0, err
}

func (rs *RedisStorage) BlockIP(ctx context.Context, ip string, reason string, duration time.Duration, requestCount int) error {
	key := fmt.Sprintf("blocked:%s", ip)
	
	info := BlockedIPInfo{
		IP:           ip,
		Reason:       reason,
		BlockedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(duration),
		RequestCount: requestCount,
	}

	data, err := json.Marshal(info)
	if err != nil {
		return err
	}

	// Store with automatic expiration
	return rs.client.Set(ctx, key, data, duration).Err()
}

func (rs *RedisStorage) UnblockIP(ctx context.Context, ip string) error {
	key := fmt.Sprintf("blocked:%s", ip)
	return rs.client.Del(ctx, key).Err()
}

func (rs *RedisStorage) GetBlockedIPs(ctx context.Context) ([]BlockedIPInfo, error) {
	keys, err := rs.client.Keys(ctx, "blocked:*").Result()
	if err != nil {
		// Return empty slice instead of nil to prevent nil pointer issues
		return []BlockedIPInfo{}, err
	}

	var blocked []BlockedIPInfo
	for _, key := range keys {
		data, err := rs.client.Get(ctx, key).Result()
		if err != nil {
			continue
		}

		var info BlockedIPInfo
		if err := json.Unmarshal([]byte(data), &info); err != nil {
			continue
		}

		blocked = append(blocked, info)
	}

	return blocked, nil
}

func (rs *RedisStorage) RecordBlockEvent(ctx context.Context, event BlockEvent) error {
	// Store in a sorted set with timestamp as score
	data, err := json.Marshal(event)
	if err != nil {
		if rs.errorLogger != nil {
			rs.errorLogger.LogError("REDIS_MARSHAL", "Failed to marshal block event", err)
		}
		return err
	}

	score := float64(event.BlockedAt.Unix())
	member := string(data)

	// Add to sorted set
	if err := rs.client.ZAdd(ctx, "block_events", redis.Z{
		Score:  score,
		Member: member,
	}).Err(); err != nil {
		if rs.errorLogger != nil {
			rs.errorLogger.LogCritical("REDIS_ZADD", "Failed to add block event to Redis sorted set", err)
		}
		return err
	}

	// Keep only last 7 days of events - with retry on failure
	cutoff := time.Now().Add(-7 * 24 * time.Hour).Unix()
	if err := rs.client.ZRemRangeByScore(ctx, "block_events", "-inf", fmt.Sprintf("%d", cutoff)).Err(); err != nil {
		// This is critical - if cleanup fails repeatedly, sorted set grows unbounded
		if rs.errorLogger != nil {
			rs.errorLogger.LogCritical("REDIS_CLEANUP", 
				fmt.Sprintf("Failed to cleanup old block events (cutoff: %d)", cutoff), err)
		}
		
		// Don't return error - event was successfully added
		// Log error and let periodic health check handle it
	}

	return nil
}

func (rs *RedisStorage) GetRecentBlockEvents(ctx context.Context, since time.Time) ([]BlockEvent, error) {
	// Get events since timestamp
	results, err := rs.client.ZRangeByScore(ctx, "block_events", &redis.ZRangeBy{
		Min: fmt.Sprintf("%d", since.Unix()),
		Max: "+inf",
	}).Result()

	if err != nil {
		return nil, err
	}

	var events []BlockEvent
	for _, data := range results {
		var event BlockEvent
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue
		}
		events = append(events, event)
	}

	return events, nil
}

func (rs *RedisStorage) Close() error {
	return rs.client.Close()
}

// StorageType returns the storage type identifier
func (rs *RedisStorage) StorageType() string {
	return "redis"
}

// SetErrorLogger sets the error logger for Redis operations
func (rs *RedisStorage) SetErrorLogger(logger ErrorLogger) {
	rs.errorLogger = logger
}

// GetBlockEventsCount returns the count of events in the Redis sorted set
// This is used for health monitoring to detect unbounded growth
func (rs *RedisStorage) GetBlockEventsCount(ctx context.Context) (int64, error) {
	count, err := rs.client.ZCard(ctx, "block_events").Result()
	if err != nil {
		if rs.errorLogger != nil {
			rs.errorLogger.LogError("REDIS_HEALTH", "Failed to get block events count", err)
		}
		return 0, err
	}
	return count, nil
}

// CleanupBlockEvents performs manual cleanup of old block events
// Returns the number of events removed
func (rs *RedisStorage) CleanupBlockEvents(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan).Unix()
	removed, err := rs.client.ZRemRangeByScore(ctx, "block_events", "-inf", fmt.Sprintf("%d", cutoff)).Result()
	if err != nil {
		if rs.errorLogger != nil {
			rs.errorLogger.LogCritical("REDIS_MANUAL_CLEANUP", 
				fmt.Sprintf("Manual cleanup failed (cutoff: %d, duration: %v)", cutoff, olderThan), err)
		}
		return 0, err
	}
	
	if removed > 0 && rs.errorLogger != nil {
		log.Printf("Manual cleanup: Removed %d old block events (older than %v)", removed, olderThan)
	}
	
	return removed, nil
}

// MemoryStorage implements in-memory storage (fallback)
type MemoryStorage struct {
	mu            sync.RWMutex // Protects blockedIPs and blockEvents
	blockedIPs    map[string]BlockedIPInfo
	blockEvents   []BlockEvent
	blockDuration time.Duration
}

func NewMemoryStorage(blockDuration time.Duration) *MemoryStorage {
	return &MemoryStorage{
		blockedIPs:    make(map[string]BlockedIPInfo),
		blockEvents:   []BlockEvent{},
		blockDuration: blockDuration,
	}
}

func (ms *MemoryStorage) IsBlocked(ctx context.Context, ip string) (bool, error) {
	ms.mu.RLock()
	info, exists := ms.blockedIPs[ip]
	ms.mu.RUnlock()

	if !exists {
		return false, nil
	}

	// Check if expired
	if time.Now().After(info.ExpiresAt) {
		ms.mu.Lock()
		delete(ms.blockedIPs, ip)
		ms.mu.Unlock()
		return false, nil
	}

	return true, nil
}

func (ms *MemoryStorage) BlockIP(ctx context.Context, ip string, reason string, duration time.Duration, requestCount int) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.blockedIPs[ip] = BlockedIPInfo{
		IP:           ip,
		Reason:       reason,
		BlockedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(duration),
		RequestCount: requestCount,
	}
	return nil
}

func (ms *MemoryStorage) UnblockIP(ctx context.Context, ip string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	delete(ms.blockedIPs, ip)
	return nil
}

func (ms *MemoryStorage) GetBlockedIPs(ctx context.Context) ([]BlockedIPInfo, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	var blocked []BlockedIPInfo
	now := time.Now()
	
	for ip, info := range ms.blockedIPs {
		if now.After(info.ExpiresAt) {
			delete(ms.blockedIPs, ip)
			continue
		}
		blocked = append(blocked, info)
	}
	
	return blocked, nil
}

func (ms *MemoryStorage) RecordBlockEvent(ctx context.Context, event BlockEvent) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.blockEvents = append(ms.blockEvents, event)
	
	// Keep only last 1000 events in memory
	if len(ms.blockEvents) > 1000 {
		ms.blockEvents = ms.blockEvents[len(ms.blockEvents)-1000:]
	}
	
	return nil
}

func (ms *MemoryStorage) GetRecentBlockEvents(ctx context.Context, since time.Time) ([]BlockEvent, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	var events []BlockEvent
	for _, event := range ms.blockEvents {
		if event.BlockedAt.After(since) {
			events = append(events, event)
		}
	}
	return events, nil
}

// InitStorage creates the appropriate storage backend
func InitStorage(redisURL string, blockDuration time.Duration) Storage {
	if redisURL != "" {
		storage, err := NewRedisStorage(redisURL, blockDuration)
		if err != nil {
			log.Printf("Failed to connect to Redis: %v, falling back to memory storage", err)
			return NewMemoryStorage(blockDuration)
		}
		log.Println("Using Redis for persistent storage")
		return storage
	}

	log.Println("Using in-memory storage (data will not persist across restarts)")
	return NewMemoryStorage(blockDuration)
}

// SetErrorLogger sets the error logger for MemoryStorage (no-op)
func (ms *MemoryStorage) SetErrorLogger(logger ErrorLogger) {
	// No-op for memory storage - it doesn't have Redis operations to log
}

// StorageType returns the storage type identifier
func (ms *MemoryStorage) StorageType() string {
	return "memory"
}

// GetBlockEventsCount returns the count of events in memory
func (ms *MemoryStorage) GetBlockEventsCount(ctx context.Context) (int64, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	return int64(len(ms.blockEvents)), nil
}

// CleanupBlockEvents performs cleanup of old block events in memory
func (ms *MemoryStorage) CleanupBlockEvents(ctx context.Context, olderThan time.Duration) (int64, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)
	var remaining []BlockEvent
	removed := 0

	for _, event := range ms.blockEvents {
		if event.BlockedAt.After(cutoff) {
			remaining = append(remaining, event)
		} else {
			removed++
		}
	}

	ms.blockEvents = remaining
	return int64(removed), nil
}
