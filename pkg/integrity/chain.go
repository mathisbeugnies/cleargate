package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// LogData represents the fields used for hashing
type LogData struct {
	Timestamp     time.Time
	UserID        string
	RequestID     string
	Verdict       string
	ThreatDetails string
	RiskScore     int
}

// CalculateHash generates SHA-256(prevHash + logData)
func CalculateHash(prevHash string, data LogData) string {
	// Canonical String Representation
	// Format: prevHash|timestamp|request_id|user_id|verdict|risk|details
	// Use UnixNano for timestamp precision
	payload := fmt.Sprintf("%s|%d|%s|%s|%s|%d|%s",
		prevHash,
		data.Timestamp.UnixMicro(),
		data.RequestID,
		data.UserID,
		data.Verdict,
		data.RiskScore,
		data.ThreatDetails,
	)

	hash := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(hash[:])
}

const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"
