package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

type Client struct {
	rdb *redis.Client
}

func NewClient(addr, password string) *Client {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password, // no password set
		DB:       0,        // use default DB
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Warn().Err(err).Msg("Failed to connect to Redis. Caching disabled.")
		return nil
	}

	return &Client{rdb: rdb}
}

// GetVerdict checks if a request hash is cached.
// Returns verdict ("SAFE", "BLOCKED") or empty string if miss.
func (c *Client) GetVerdict(ctx context.Context, hash string) string {
	if c == nil || c.rdb == nil {
		return ""
	}
	val, err := c.rdb.Get(ctx, hash).Result()
	if err == redis.Nil {
		return ""
	} else if err != nil {
		log.Error().Err(err).Msg("Redis Get Error")
		return ""
	}
	return val
}

// SetVerdict caches a request result.
func (c *Client) SetVerdict(ctx context.Context, hash string, verdict string, ttl time.Duration) {
	if c == nil || c.rdb == nil {
		return
	}
	if err := c.rdb.Set(ctx, hash, verdict, ttl).Err(); err != nil {
		log.Error().Err(err).Msg("Redis Set Error")
	}
}

// InvalidateOrg clears all cache entries for a specific organization.
// Pattern: "org:{orgID}:*"
// Note: This relies on keys being prefixed properly.
// The Hash calculated in handler needs to be part of the Key.
// Key Format: "org:{orgID}:{hash}"
func (c *Client) InvalidateOrg(ctx context.Context, orgID int) {
	if c == nil || c.rdb == nil {
		return
	}
	pattern := fmt.Sprintf("org:%d:*", orgID)

	// Scan and Delete (Safe for production than KEYS)
	iter := c.rdb.Scan(ctx, 0, pattern, 0).Iterator()
	for iter.Next(ctx) {
		c.rdb.Del(ctx, iter.Val())
	}
	if err := iter.Err(); err != nil {
		log.Error().Err(err).Msg("Redis Invalidate Error")
	}
	log.Info().Int("org_id", orgID).Msg("Invalidated Organization Cache")
}

// Incr increments a key and sets expiration if new
func (c *Client) Incr(ctx context.Context, key string, ttl time.Duration) int64 {
	if c == nil || c.rdb == nil {
		return 0
	}
	pipe := c.rdb.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	if err != nil {
		log.Error().Err(err).Str("key", key).Msg("Redis Incr Error")
		return 0
	}
	return incr.Val()
}

// BlockUser sets a block key for a user
func (c *Client) BlockUser(ctx context.Context, userID string, duration time.Duration) {
	if c == nil || c.rdb == nil {
		return
	}
	key := fmt.Sprintf("user:%s:blocked", userID)
	if err := c.rdb.Set(ctx, key, "BLOCKED", duration).Err(); err != nil {
		log.Error().Err(err).Str("user_id", userID).Msg("Failed to block user")
	}
}

// IsBlocked checks if a user is blocked
func (c *Client) IsBlocked(ctx context.Context, userID string) bool {
	if c == nil || c.rdb == nil {
		return false
	}
	key := fmt.Sprintf("user:%s:blocked", userID)
	val, err := c.rdb.Get(ctx, key).Result()
	if err == redis.Nil {
		return false
	}
	return val == "BLOCKED"
}

// VAULT METHODS

// SetVault stores the Detokenization Map for a request
func (c *Client) SetVault(ctx context.Context, reqID string, mapping map[string]string, ttl time.Duration) {
	if c == nil || c.rdb == nil || len(mapping) == 0 {
		return
	}
	// Store as Hash or JSON string? JSON string is simpler for "whole map" retrieval
	// But Hash (HSET) allows per-field access. Vault usually needs whole map to Rehydrate.
	key := fmt.Sprintf("vault:%s", reqID)

	// We use HSET for mapping so we can technically add to it if needed,
	// but Set (JSON) is faster for one-shot.
	// Let's use HSET for clarity: Field=Token, Value=Real
	// Convert map[string]string to []interface{} isn't direct.
	// JSON is safest for arbitrary data.
	// But wait, HSET accepts map[string]string directly in go-redis v9!

	if err := c.rdb.HSet(ctx, key, mapping).Err(); err != nil {
		log.Error().Err(err).Str("req_id", reqID).Msg("Vault: Failed to store tokens")
	}
	c.rdb.Expire(ctx, key, ttl)
}

// GetVault retrieves the Detokenization Map
func (c *Client) GetVault(ctx context.Context, reqID string) map[string]string {
	if c == nil || c.rdb == nil {
		return nil
	}
	key := fmt.Sprintf("vault:%s", reqID)
	res, err := c.rdb.HGetAll(ctx, key).Result()
	if err != nil {
		if err != redis.Nil {
			log.Error().Err(err).Str("req_id", reqID).Msg("Vault: Failed to retrieve tokens")
		}
		return nil
	}
	return res
}
