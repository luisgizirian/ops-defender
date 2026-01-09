package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
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
	BlockIP(ctx context.Context, ip string, reason string, duration time.Duration) error
	UnblockIP(ctx context.Context, ip string) error
	GetBlockedIPs(ctx context.Context) ([]BlockedIPInfo, error)
	RecordBlockEvent(ctx context.Context, event BlockEvent) error
	GetRecentBlockEvents(ctx context.Context, since time.Time) ([]BlockEvent, error)
}

type BlockedIPInfo struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	BlockedAt time.Time `json:"blocked_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RedisStorage implements persistent storage with Redis
type RedisStorage struct {
	client        *redis.Client
	blockDuration time.Duration
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

func (rs *RedisStorage) BlockIP(ctx context.Context, ip string, reason string, duration time.Duration) error {
	key := fmt.Sprintf("blocked:%s", ip)
	
	info := BlockedIPInfo{
		IP:        ip,
		Reason:    reason,
		BlockedAt: time.Now(),
		ExpiresAt: time.Now().Add(duration),
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
		return err
	}

	score := float64(event.BlockedAt.Unix())
	member := string(data)

	// Add to sorted set
	if err := rs.client.ZAdd(ctx, "block_events", redis.Z{
		Score:  score,
		Member: member,
	}).Err(); err != nil {
		return err
	}

	// Keep only last 7 days of events
	cutoff := time.Now().Add(-7 * 24 * time.Hour).Unix()
	return rs.client.ZRemRangeByScore(ctx, "block_events", "-inf", fmt.Sprintf("%d", cutoff)).Err()
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

// MemoryStorage implements in-memory storage (fallback)
type MemoryStorage struct {
	blockedIPs  map[string]BlockedIPInfo
	blockEvents []BlockEvent
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
	info, exists := ms.blockedIPs[ip]
	if !exists {
		return false, nil
	}

	// Check if expired
	if time.Now().After(info.ExpiresAt) {
		delete(ms.blockedIPs, ip)
		return false, nil
	}

	return true, nil
}

func (ms *MemoryStorage) BlockIP(ctx context.Context, ip string, reason string, duration time.Duration) error {
	ms.blockedIPs[ip] = BlockedIPInfo{
		IP:        ip,
		Reason:    reason,
		BlockedAt: time.Now(),
		ExpiresAt: time.Now().Add(duration),
	}
	return nil
}

func (ms *MemoryStorage) UnblockIP(ctx context.Context, ip string) error {
	delete(ms.blockedIPs, ip)
	return nil
}

func (ms *MemoryStorage) GetBlockedIPs(ctx context.Context) ([]BlockedIPInfo, error) {
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
	ms.blockEvents = append(ms.blockEvents, event)
	
	// Keep only last 1000 events in memory
	if len(ms.blockEvents) > 1000 {
		ms.blockEvents = ms.blockEvents[len(ms.blockEvents)-1000:]
	}
	
	return nil
}

func (ms *MemoryStorage) GetRecentBlockEvents(ctx context.Context, since time.Time) ([]BlockEvent, error) {
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
