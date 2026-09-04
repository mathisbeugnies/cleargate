package storage

import (
	"cleargate/pkg/integrity"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

// Organization represents a tenant using the system.
type Organization struct {
	ID        int
	Name      string
	ApiKey    string `json:"-"` // stored hashed; never serialized to clients
	PublicKey string // RSA Public Key (PEM)
}

// HashAPIKey returns the storage representation of an API key. Keys are
// high-entropy, so an unsalted SHA-256 is enough and keeps lookups O(1).
func HashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// Policy is the security configuration associated with an organization.
type Policy struct {
	ID             int
	OrganizationID int
	Config         string // JSON
}

// RequestMetadata contains all details about a processed request for audit logging.
type RequestMetadata struct {
	Timestamp         time.Time `json:"timestamp"`
	UserID            string    `json:"user_id"`
	Provider          string    `json:"provider"`
	InterceptedFields []string  `json:"intercepted_fields"`
	Sanitized         bool      `json:"sanitized"`
	RiskScore         int       `json:"risk_score"`
	RequestID         string    `json:"request_id"`
	PromptHash        string    `json:"prompt_hash"`
	Verdict           string    `json:"verdict"`
	ThreatDetails     string    `json:"threat_details"`
	SimilarityScore   float32   `json:"similarity_score"`

	OrganizationID  int    `json:"organization_id"`
	PromptEncrypted string `json:"prompt_encrypted"`
	Latency         int64  `json:"latency"`
}

// Store handles PostgreSQL database interactions.
type Store struct {
	db *sql.DB
}

// NewStore connects to the database and returns a Store instance.
func NewStore(dsn string) (*Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// The database container often isn't accepting connections yet when the
	// app starts, so retry with backoff instead of failing immediately.
	var pingErr error
	for attempt := 0; attempt < 30; attempt++ {
		if pingErr = db.Ping(); pingErr == nil {
			return &Store{db: db}, nil
		}
		time.Sleep(time.Second)
	}
	return nil, fmt.Errorf("database not reachable after 30s: %w", pingErr)
}

// Ping checks that the database is reachable.
func (s *Store) Ping() error { return s.db.Ping() }

// Close releases the connection pool.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) InitSchema() error {
	// Organizations Table
	orgsQuery := `
	CREATE TABLE IF NOT EXISTS organizations (
		id SERIAL PRIMARY KEY,
		name TEXT NOT NULL,
		api_key TEXT UNIQUE NOT NULL,
		public_key TEXT DEFAULT ''
	);`

	// Policies Table
	policiesQuery := `
	CREATE TABLE IF NOT EXISTS policies (
		id SERIAL PRIMARY KEY,
		organization_id INTEGER REFERENCES organizations(id),
		config TEXT DEFAULT '{}'
	);`

	// Request Logs Table
	requestLogsQuery := `
	CREATE TABLE IF NOT EXISTS request_logs (
		id SERIAL PRIMARY KEY,
		request_id TEXT,
		timestamp TIMESTAMP,
		user_id TEXT,
		provider TEXT,
		intercepted_fields TEXT,
		sanitized BOOLEAN,
		risk_score INTEGER DEFAULT 0,
		prompt_hash TEXT,
		verdict TEXT,
		threat_details TEXT,
		similarity_score REAL DEFAULT 0,
		organization_id INTEGER DEFAULT 0
	);`

	// Users Table
	usersQuery := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role TEXT DEFAULT 'user',
		organization_id INTEGER REFERENCES organizations(id)
	);`

	// Invitations Table
	invitationsQuery := `
	CREATE TABLE IF NOT EXISTS invitations (
		id SERIAL PRIMARY KEY,
		token TEXT UNIQUE NOT NULL,
		email TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'org_admin',
		organization_id INTEGER REFERENCES organizations(id),
		expires_at TIMESTAMP NOT NULL,
		used BOOLEAN DEFAULT FALSE
	);`

	// Documents Table (RAG)
	documentsQuery := `
	CREATE TABLE IF NOT EXISTS documents (
		id SERIAL PRIMARY KEY,
		organization_id INTEGER REFERENCES organizations(id),
		filename TEXT NOT NULL,
		size_bytes INTEGER NOT NULL,
		chunks_count INTEGER NOT NULL,
		uploaded_at TIMESTAMP NOT NULL
	);`

	if _, err := s.db.Exec(orgsQuery); err != nil {
		return err
	}
	if _, err := s.db.Exec(policiesQuery); err != nil {
		return err
	}
	if _, err := s.db.Exec(requestLogsQuery); err != nil {
		return err
	}
	if _, err := s.db.Exec(usersQuery); err != nil {
		return err
	}
	if _, err := s.db.Exec(invitationsQuery); err != nil {
		return err
	}
	if _, err := s.db.Exec(documentsQuery); err != nil {
		return err
	}

	// Migrations
	s.db.Exec(`ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS organization_id INTEGER DEFAULT 0;`)
	s.db.Exec(`ALTER TABLE organizations ADD COLUMN IF NOT EXISTS public_key TEXT DEFAULT '';`)
	s.db.Exec(`ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS previous_hash TEXT DEFAULT '';`)
	s.db.Exec(`ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS previous_hash TEXT DEFAULT '';`)
	s.db.Exec(`ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS current_hash TEXT DEFAULT '';`)
	s.db.Exec(`ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS current_hash TEXT DEFAULT '';`)
	s.db.Exec(`ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS prompt_encrypted TEXT DEFAULT '';`)
	s.db.Exec(`ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS latency_ms INTEGER DEFAULT 0;`)

	s.bootstrapSuperAdmin()
	return nil
}

// bootstrapSuperAdmin creates the first super_admin only from explicit
// environment variables, and only when there are no users yet. It never
// invents credentials, never logs a password, and never promotes an account
// by a well-known email address.
func (s *Store) bootstrapSuperAdmin() {
	var userCount int
	s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	if userCount > 0 {
		return
	}

	email := strings.ToLower(strings.TrimSpace(os.Getenv("SUPERADMIN_EMAIL")))
	password := os.Getenv("SUPERADMIN_PASSWORD")
	if email == "" || password == "" {
		log.Warn().Msg("No users yet. Set SUPERADMIN_EMAIL and SUPERADMIN_PASSWORD to create the first admin, or register an organization via POST /api/signup.")
		return
	}
	if len(password) < 12 {
		log.Error().Msg("SUPERADMIN_PASSWORD must be at least 12 characters; skipping bootstrap.")
		return
	}

	var orgID int
	if err := s.db.QueryRow(
		`INSERT INTO organizations (name, api_key) VALUES ($1, $2) RETURNING id`,
		"Default Org", HashAPIKey("sk-"+uuid.New().String()),
	).Scan(&orgID); err != nil {
		log.Error().Err(err).Msg("bootstrapSuperAdmin: failed to create org")
		return
	}

	defaultConfig := `{"email_redaction":true,"phone_redaction":true,"api_key_detection":true,"source_code_dlp":true,"prompt_injection":true,"vector_guard":true}`
	s.db.Exec(`INSERT INTO policies (organization_id, config) VALUES ($1, $2)`, orgID, defaultConfig)

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error().Err(err).Msg("bootstrapSuperAdmin: failed to hash password")
		return
	}
	if _, err := s.db.Exec(
		`INSERT INTO users (email, password_hash, role, organization_id) VALUES ($1, $2, $3, $4)`,
		email, string(hash), "super_admin", orgID,
	); err != nil {
		log.Error().Err(err).Msg("bootstrapSuperAdmin: failed to create user")
		return
	}
	log.Info().Str("email", email).Msg("Created initial super_admin from environment")
}

type User struct {
	ID             int
	Email          string
	PasswordHash   string
	Role           string
	OrganizationID int
}

func (s *Store) CreateUser(email, passwordHash, role string, orgID int) error {
	_, err := s.db.Exec(`INSERT INTO users (email, password_hash, role, organization_id) VALUES ($1, $2, $3, $4)`,
		email, passwordHash, role, orgID)
	return err
}

func (s *Store) GetUserByEmail(email string) (*User, error) {
	var u User
	err := s.db.QueryRow(`SELECT id, email, password_hash, role, organization_id FROM users WHERE email = $1`, email).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.OrganizationID)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

type Invitation struct {
	ID             int
	Token          string
	Email          string
	Role           string
	OrganizationID int
	ExpiresAt      time.Time
	Used           bool
}

func (s *Store) CreateInvitation(inv Invitation) error {
	_, err := s.db.Exec(`INSERT INTO invitations (token, email, role, organization_id, expires_at) VALUES ($1, $2, $3, $4, $5)`,
		inv.Token, inv.Email, inv.Role, inv.OrganizationID, inv.ExpiresAt)
	return err
}

func (s *Store) GetInvitationByToken(token string) (*Invitation, error) {
	var i Invitation
	err := s.db.QueryRow(`SELECT id, token, email, role, organization_id, expires_at, used FROM invitations WHERE token = $1`, token).
		Scan(&i.ID, &i.Token, &i.Email, &i.Role, &i.OrganizationID, &i.ExpiresAt, &i.Used)
	if err != nil {
		return nil, err
	}
	return &i, nil
}

func (s *Store) MarkInvitationUsed(id int) error {
	_, err := s.db.Exec(`UPDATE invitations SET used = TRUE WHERE id = $1`, id)
	return err
}

// CreateOrganization stores the org with a hashed API key. The caller keeps
// the only copy of the plaintext key.
func (s *Store) CreateOrganization(name, apiKey string) (int, error) {
	var id int
	err := s.db.QueryRow(`INSERT INTO organizations (name, api_key) VALUES ($1, $2) RETURNING id`,
		name, HashAPIKey(apiKey)).Scan(&id)
	return id, err
}

func (s *Store) GetOrganizations() ([]Organization, error) {
	rows, err := s.db.Query(`SELECT id, name, api_key, COALESCE(public_key, '') FROM organizations ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var orgs []Organization
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.ApiKey, &o.PublicKey); err != nil {
			return nil, err
		}
		orgs = append(orgs, o)
	}
	return orgs, nil
}

// LogRequest inserts an immutable audit log entry into the database.
// It enforces cryptographic hash chaining to ensure integrity.
func (s *Store) LogRequest(meta RequestMetadata) {
	// Normalize Timestamp to ensure Hash Consistency
	// Postgres stores Microseconds. Go has Nanoseconds.
	// Also ensure UTC to avoid Timezone shifts affecting UnixMicro().
	meta.Timestamp = meta.Timestamp.UTC().Truncate(time.Microsecond)

	fields := strings.Join(meta.InterceptedFields, ",")

	// Transaction for Hash Chaining Integrity
	tx, err := s.db.Begin()
	if err != nil {
		log.Error().Err(err).Msg("Failed to begin transaction for logging")
		return
	}
	defer tx.Rollback()

	// 1. Serialize inserts per organization (not globally) so each org has its
	// own hash chain and one tenant's traffic can't stall another's.
	if _, err := tx.Exec("SELECT pg_advisory_xact_lock(4711, $1)", meta.OrganizationID); err != nil {
		log.Error().Err(err).Msg("Failed to acquire per-org log lock")
		return
	}

	var prevHash string
	err = tx.QueryRow(
		"SELECT current_hash FROM request_logs WHERE organization_id = $1 ORDER BY id DESC LIMIT 1",
		meta.OrganizationID,
	).Scan(&prevHash)
	if err == sql.ErrNoRows {
		prevHash = integrity.GenesisHash
	} else if err != nil {
		log.Error().Err(err).Msg("Failed to fetch previous hash")
		return
	}
	if prevHash == "" {
		prevHash = integrity.GenesisHash
	}

	// 2. Calculate New Hash
	data := integrity.LogData{
		Timestamp:     meta.Timestamp,
		UserID:        meta.UserID,
		RequestID:     meta.RequestID,
		Verdict:       meta.Verdict,
		ThreatDetails: meta.ThreatDetails,

		RiskScore: meta.RiskScore,
	}
	currentHash := integrity.CalculateHash(prevHash, data)

	// 3. Insert
	query := `INSERT INTO request_logs (
		timestamp, user_id, provider, intercepted_fields, sanitized, risk_score,
		request_id, prompt_hash, verdict, threat_details, similarity_score, organization_id,
		previous_hash, current_hash, prompt_encrypted, latency_ms
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`

	_, err = tx.Exec(query,
		meta.Timestamp, meta.UserID, meta.Provider, fields, meta.Sanitized, meta.RiskScore,
		meta.RequestID, meta.PromptHash, meta.Verdict, meta.ThreatDetails, meta.SimilarityScore, meta.OrganizationID,
		prevHash, currentHash, meta.PromptEncrypted, meta.Latency,
	)

	if err != nil {
		log.Error().Err(err).Msg("Failed to log request to DB")
		return
	}

	if err := tx.Commit(); err != nil {
		log.Error().Err(err).Msg("Failed to commit log transaction")
	} else {
		log.Info().Str("request_id", meta.RequestID).Int("org_id", meta.OrganizationID).Msg("Audit Log recorded with Integrity Hash")
	}
}

func (s *Store) GetOrganizationByKey(apiKey string) (*Organization, error) {
	query := `SELECT id, name, api_key, COALESCE(public_key, '') FROM organizations WHERE api_key = $1`
	var org Organization
	err := s.db.QueryRow(query, HashAPIKey(apiKey)).Scan(&org.ID, &org.Name, &org.ApiKey, &org.PublicKey)
	if err != nil {
		return nil, err
	}
	return &org, nil
}

func (s *Store) UpdateOrganizationKey(orgID int, pubKey string) error {
	_, err := s.db.Exec(`UPDATE organizations SET public_key = $1 WHERE id = $2`, pubKey, orgID)
	return err
}

func (s *Store) GetPublicKey(orgID int) (string, error) {
	var key string
	err := s.db.QueryRow(`SELECT COALESCE(public_key, '') FROM organizations WHERE id = $1`, orgID).Scan(&key)
	return key, err
}

func (s *Store) GetPolicyByOrgID(orgID int) (string, error) {
	query := `SELECT config FROM policies WHERE organization_id = $1`
	var config string
	err := s.db.QueryRow(query, orgID).Scan(&config)
	if err != nil {
		return "{}", nil
	}
	return config, nil
}

func (s *Store) UpdatePolicy(orgID int, config string) error {
	var exists bool
	s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM policies WHERE organization_id=$1)", orgID).Scan(&exists)

	if exists {
		_, err := s.db.Exec("UPDATE policies SET config=$1 WHERE organization_id=$2", config, orgID)
		return err
	} else {
		_, err := s.db.Exec("INSERT INTO policies (organization_id, config) VALUES ($1, $2)", orgID, config)
		return err
	}
}

type AuditLogFilter struct {
	UserID    string
	RiskLevel string // LOW, MEDIUM, HIGH
	Verdict   string // BLOCK, MODIFY, PASS
	From      time.Time
	To        time.Time
	Limit     int
	Offset    int
	Search    string // Generic text search (details, user, request_id)
}

func (s *Store) GetAuditLogs(orgID int, filter AuditLogFilter) ([]RequestMetadata, error) {
	baseQuery := `SELECT timestamp, COALESCE(user_id, ''), COALESCE(provider, ''), COALESCE(intercepted_fields, ''), sanitized, risk_score, COALESCE(request_id, ''), COALESCE(prompt_hash, ''), COALESCE(verdict, ''), COALESCE(threat_details, ''), similarity_score, organization_id, COALESCE(prompt_encrypted, '') FROM request_logs WHERE organization_id = $1`

	var args []interface{}
	args = append(args, orgID)
	argCount := 2

	var conditions []string

	if filter.UserID != "" {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argCount))
		args = append(args, filter.UserID)
		argCount++
	}

	if filter.Verdict != "" {
		conditions = append(conditions, fmt.Sprintf("verdict = $%d", argCount))
		args = append(args, filter.Verdict)
		argCount++
	}

	if filter.RiskLevel != "" {
		// Risk Level mapping: HIGH > 80, MEDIUM > 0, LOW = 0
		if filter.RiskLevel == "HIGH" {
			conditions = append(conditions, fmt.Sprintf("risk_score > $%d", argCount))
			args = append(args, 80)
			argCount++
		} else if filter.RiskLevel == "MEDIUM" {
			conditions = append(conditions, "risk_score > 0 AND risk_score <= 80")
		} else if filter.RiskLevel == "LOW" {
			conditions = append(conditions, "risk_score = 0")
		}
	}

	if !filter.From.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argCount))
		args = append(args, filter.From)
		argCount++
	}

	if !filter.To.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argCount))
		args = append(args, filter.To)
		argCount++
	}

	if filter.Search != "" {
		// ILIKE for case-insensitive search
		likePattern := "%" + filter.Search + "%"
		conditions = append(conditions, fmt.Sprintf("(user_id ILIKE $%d OR request_id ILIKE $%d OR threat_details ILIKE $%d)", argCount, argCount, argCount))
		args = append(args, likePattern)
		argCount++
	}

	query := baseQuery
	if len(conditions) > 0 {
		query += " AND " + strings.Join(conditions, " AND ")
	}

	// Order & Pagination
	query += " ORDER BY timestamp DESC"

	limit := 100
	if filter.Limit > 0 {
		limit = filter.Limit
	}
	query += fmt.Sprintf(" LIMIT $%d", argCount)
	args = append(args, limit)
	argCount++

	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argCount)
		args = append(args, filter.Offset)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	logs := make([]RequestMetadata, 0)
	for rows.Next() {
		var m RequestMetadata
		var fields string
		err := rows.Scan(
			&m.Timestamp, &m.UserID, &m.Provider, &fields, &m.Sanitized, &m.RiskScore,
			&m.RequestID, &m.PromptHash, &m.Verdict, &m.ThreatDetails, &m.SimilarityScore, &m.OrganizationID, &m.PromptEncrypted,
		)
		if err != nil {
			return nil, err
		}
		m.InterceptedFields = strings.Split(fields, ",")
		logs = append(logs, m)
	}
	return logs, nil
}

type Stats struct {
	TotalRequests       int
	TotalRequestsTrend  int
	BlockedCount        int
	BlockedCountTrend   int
	SanitizedCount      int
	SanitizedCountTrend int
	AvgLatency          string
	AvgLatencyTrend     int
}

func (s *Store) GetStats(orgID int) (*Stats, error) {
	stats := &Stats{}

	// Helper to calculate trend
	calcTrend := func(curr, prev int) int {
		if prev == 0 {
			if curr > 0 {
				return 100
			}
			return 0
		}
		return int(float64(curr-prev) / float64(prev) * 100)
	}

	// 1. Total Requests (Current 24h vs Previous 24h)
	var currTotal, prevTotal int
	s.db.QueryRow(`
		SELECT 
			COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 HOURS'),
			COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '48 HOURS' AND timestamp < NOW() - INTERVAL '24 HOURS')
		FROM request_logs WHERE organization_id = $1`, orgID).Scan(&currTotal, &prevTotal)

	// We return the TOTAL All-Time count for the main value, but trend is based on 24h activity?
	// Usually "Total Requests" on a dashboard implies "Total for selected period" or "All Time".
	// Given "NaN" was fixed by "SELECT COUNT(*)", that was All Time.
	// But Trend requires a period. Let's keep Main Value = All Time, Trend = Activity Change (Last 24h vs Prev 24h).
	// Actually, usually Main Value matches the Trend period (e.g. "Last 7 Days").
	// But for "Total Requests" showing 5 vs 10000 is different.
	// Let's stick to All Time for the Big Number, and Trend is "24h Velocity Change".

	// Re-query for All Time Total
	s.db.QueryRow("SELECT COUNT(*) FROM request_logs WHERE organization_id = $1", orgID).Scan(&stats.TotalRequests)
	stats.TotalRequestsTrend = calcTrend(currTotal, prevTotal)

	// 2. Blocked
	var currBlock, prevBlock int
	s.db.QueryRow(`
		SELECT 
			COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 HOURS'),
			COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '48 HOURS' AND timestamp < NOW() - INTERVAL '24 HOURS')
		FROM request_logs WHERE organization_id = $1 AND verdict = 'BLOCK'`, orgID).Scan(&currBlock, &prevBlock)

	s.db.QueryRow("SELECT COUNT(*) FROM request_logs WHERE organization_id = $1 AND verdict = 'BLOCK'", orgID).Scan(&stats.BlockedCount)
	stats.BlockedCountTrend = calcTrend(currBlock, prevBlock)

	// 3. Sanitized
	var currSan, prevSan int
	s.db.QueryRow(`
		SELECT 
			COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 HOURS'),
			COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '48 HOURS' AND timestamp < NOW() - INTERVAL '24 HOURS')
		FROM request_logs WHERE organization_id = $1 AND sanitized = TRUE`, orgID).Scan(&currSan, &prevSan)

	s.db.QueryRow("SELECT COUNT(*) FROM request_logs WHERE organization_id = $1 AND sanitized = TRUE", orgID).Scan(&stats.SanitizedCount)
	stats.SanitizedCountTrend = calcTrend(currSan, prevSan)

	// 4. Latency
	var avgLatency float64
	err := s.db.QueryRow("SELECT COALESCE(AVG(latency_ms), 0) FROM request_logs WHERE organization_id = $1", orgID).Scan(&avgLatency)
	if err == nil {
		stats.AvgLatency = fmt.Sprintf("%.0fms", avgLatency)
	} else {
		stats.AvgLatency = "0ms"
	}
	// Latency Trend? (Current Avg vs Prev Avg)
	var currLat, prevLat float64
	s.db.QueryRow(`
		SELECT 
			COALESCE(AVG(latency_ms) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 HOURS'), 0),
			COALESCE(AVG(latency_ms) FILTER (WHERE timestamp >= NOW() - INTERVAL '48 HOURS' AND timestamp < NOW() - INTERVAL '24 HOURS'), 0)
		FROM request_logs WHERE organization_id = $1`, orgID).Scan(&currLat, &prevLat)

	if prevLat == 0 {
		stats.AvgLatencyTrend = 0
	} else {
		stats.AvgLatencyTrend = int(((currLat - prevLat) / prevLat) * 100)
	}

	return stats, nil
}

type IntegrityReport struct {
	Valid        bool   `json:"valid"`
	BrokenAtID   int    `json:"broken_at_id"`
	TotalChecked int    `json:"total_checked"`
	Error        string `json:"error"`
}

func (s *Store) VerifyIntegrity(orgID int) (*IntegrityReport, error) {
	// Traverse this organization's chain in insertion order.
	query := `SELECT id, timestamp, user_id, request_id, verdict, threat_details, risk_score, previous_hash, current_hash
	          FROM request_logs WHERE organization_id = $1 ORDER BY id ASC`

	rows, err := s.db.Query(query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	report := &IntegrityReport{Valid: true, TotalChecked: 0}

	// Track the expected hash for the next row
	expectedPrevHash := integrity.GenesisHash

	for rows.Next() {
		var id, riskScore int
		var ts time.Time
		var userID, reqID, verdict, details, prevHash, currHash string

		// Fix: handle NULLs safely?
		// Schema has DEFAULT '', but if old rows exist without hash?
		// Migrations added columns with DEFAULT '', so they should be empty strings.
		if err := rows.Scan(&id, &ts, &userID, &reqID, &verdict, &details, &riskScore, &prevHash, &currHash); err != nil {
			return nil, err
		}

		// Skip genesis check for existing legacy records if they have empty hashes?
		// No, if they have empty hashes, the chain is effectively "broken" or resets.
		// Detailed logic:
		// If current_hash is empty, maybe it's a legacy row.
		// But we want to enforce integrity.
		// Let's assume migration didn't backfill hashes.
		// If currHash is empty, we flag it or skip?
		// For strict integrity, any row without a valid hash is a violation.

		// 1. Check if Previous Hash matches what we expect
		if prevHash != expectedPrevHash {
			report.Valid = false
			report.BrokenAtID = id
			report.Error = fmt.Sprintf("Chain Broken: Previous Hash mismatch (Expected %s, Got %s)", expectedPrevHash, prevHash)
			return report, nil
		}

		// 2. Calculate Expected Current Hash
		data := integrity.LogData{
			Timestamp:     ts,
			UserID:        userID,
			RequestID:     reqID,
			Verdict:       verdict,
			ThreatDetails: details,
			RiskScore:     riskScore,
		}
		calculatedHash := integrity.CalculateHash(prevHash, data)

		// 3. Compare with Stored Hash
		if calculatedHash != currHash {
			report.Valid = false
			report.BrokenAtID = id
			report.Error = "Data Tampering: Hash Mismatch"
			return report, nil
		}

		// Set next expected
		expectedPrevHash = currHash
		report.TotalChecked++
	}

	return report, nil
}

type Document struct {
	ID          int       `json:"id"`
	Filename    string    `json:"filename"`
	Size        int       `json:"size_bytes"`
	ChunksCount int       `json:"chunks_count"`
	UploadedAt  time.Time `json:"uploaded_at"`
}

func (s *Store) CreateDocument(orgID int, filename string, size int, chunks int) error {
	_, err := s.db.Exec("INSERT INTO documents (organization_id, filename, size_bytes, chunks_count, uploaded_at) VALUES ($1, $2, $3, $4, $5)",
		orgID, filename, size, chunks, time.Now())
	return err
}

func (s *Store) ListDocuments(orgID int) ([]Document, error) {
	rows, err := s.db.Query("SELECT id, filename, size_bytes, chunks_count, uploaded_at FROM documents WHERE organization_id = $1 ORDER BY uploaded_at DESC", orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var docs []Document
	for rows.Next() {
		var d Document
		if err := rows.Scan(&d.ID, &d.Filename, &d.Size, &d.ChunksCount, &d.UploadedAt); err != nil {
			return nil, err
		}
		docs = append(docs, d)
	}
	// Return empty slice if nil
	if docs == nil {
		return make([]Document, 0), nil
	}
	return docs, nil
}

func (s *Store) DeleteDocument(orgID int, docID int) (string, error) {
	var filename string
	err := s.db.QueryRow("DELETE FROM documents WHERE id = $1 AND organization_id = $2 RETURNING filename", docID, orgID).Scan(&filename)
	return filename, err
}

// DeleteOldAuditLogs removes logs older than `days` for a single organization.
func (s *Store) DeleteOldAuditLogs(orgID, days int) (int64, error) {
	threshold := time.Now().AddDate(0, 0, -days)
	res, err := s.db.Exec(
		"DELETE FROM request_logs WHERE organization_id = $1 AND timestamp < $2",
		orgID, threshold)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
