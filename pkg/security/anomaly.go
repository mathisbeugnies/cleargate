package security

import (
	"cleargate/pkg/cache"
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

type AnomalyDetector struct {
	cache *cache.Client
}

func NewAnomalyDetector(cacheClient *cache.Client) *AnomalyDetector {
	return &AnomalyDetector{cache: cacheClient}
}

// CheckAccess verifies if the user is allowed to proceed (not blocked)
func (d *AnomalyDetector) CheckAccess(ctx context.Context, userID string) (bool, string) {
	if d.cache == nil {
		return true, ""
	}
	if d.cache.IsBlocked(ctx, userID) {
		return false, "User Account Locked due to Suspicious Activity"
	}
	return true, ""
}

// TrackRisk increments risk counter and blocks if threshold exceeded
func (d *AnomalyDetector) TrackRisk(ctx context.Context, userID string, riskScore int) {
	if d.cache == nil || riskScore < 70 {
		return
	}

	key := fmt.Sprintf("user:%s:risk_events:10m", userID)
	// Increment risk event counter (10 min window)
	count := d.cache.Incr(ctx, key, 10*time.Minute)

	if count > 5 {
		log.Warn().Str("user_id", userID).Int64("risk_count", count).Msg("Blocking user due to repeated high-risk activity")
		d.cache.BlockUser(ctx, userID, 1*time.Hour)
	}
}

// TrackUsage monitors token/request volume
func (d *AnomalyDetector) TrackUsage(ctx context.Context, userID string, tokens int) {
	if d.cache == nil {
		return
	}

	// 1. Request Rate
	reqKey := fmt.Sprintf("user:%s:req:1h", userID)
	reqCount := d.cache.Incr(ctx, reqKey, 1*time.Hour)

	// Baseline Check (Mock Baseline: 1000 reqs/hour)
	if reqCount > 1000 { // 300% of ~300
		log.Warn().Str("user_id", userID).Int64("req_count", reqCount).Msg("Anomalous Usage Detected: High Request Rate")
		// Could mark for Audit here
	}
}
