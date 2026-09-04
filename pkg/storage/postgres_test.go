package storage

import (
	"os"
	"testing"
	"time"
)

// testStore connects to TEST_DATABASE_URL (or DATABASE_URL) and gives every
// test a clean schema. If neither is set the whole file is skipped, so
// `go test ./...` still passes without a database.
func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run storage integration tests")
	}

	s, err := NewStore(dsn)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	for _, tbl := range []string{"request_logs", "documents", "invitations", "users", "policies", "organizations"} {
		if _, err := s.db.Exec("DROP TABLE IF EXISTS " + tbl + " CASCADE"); err != nil {
			t.Fatalf("drop %s: %v", tbl, err)
		}
	}
	if err := s.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOrganizationAPIKeyIsHashed(t *testing.T) {
	s := testStore(t)

	const key = "sk-plaintext-value-1234567890"
	orgID, err := s.CreateOrganization("Acme", key)
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}

	var stored string
	s.db.QueryRow("SELECT api_key FROM organizations WHERE id=$1", orgID).Scan(&stored)
	if stored == key {
		t.Fatal("API key stored in plaintext")
	}
	if stored != HashAPIKey(key) {
		t.Fatalf("stored value is not the SHA-256 of the key")
	}

	got, err := s.GetOrganizationByKey(key)
	if err != nil || got.ID != orgID {
		t.Fatalf("lookup by plaintext key failed: %v", err)
	}
	if _, err := s.GetOrganizationByKey("sk-wrong"); err == nil {
		t.Fatal("lookup with a wrong key should fail")
	}
}

func TestUserRoundTrip(t *testing.T) {
	s := testStore(t)
	orgID, _ := s.CreateOrganization("Org", "sk-k")

	if err := s.CreateUser("user@x.com", "hash", "org_admin", orgID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	u, err := s.GetUserByEmail("user@x.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if u.Role != "org_admin" || u.OrganizationID != orgID {
		t.Fatalf("bad user: %+v", u)
	}
}

func TestAuditChainAndScoping(t *testing.T) {
	s := testStore(t)
	orgA, _ := s.CreateOrganization("A", "sk-a")
	orgB, _ := s.CreateOrganization("B", "sk-b")

	for i := 0; i < 5; i++ {
		s.LogRequest(RequestMetadata{
			Timestamp: time.Now(), RequestID: "a-" + string(rune('0'+i)),
			Verdict: "PASS", OrganizationID: orgA,
		})
	}
	s.LogRequest(RequestMetadata{Timestamp: time.Now(), RequestID: "b-1", Verdict: "PASS", OrganizationID: orgB})

	rep, err := s.VerifyIntegrity(orgA)
	if err != nil {
		t.Fatalf("VerifyIntegrity: %v", err)
	}
	if !rep.Valid || rep.TotalChecked != 5 {
		t.Fatalf("org A chain: valid=%v checked=%d", rep.Valid, rep.TotalChecked)
	}

	// Deleting old logs for A must not touch B.
	var beforeB int
	s.db.QueryRow("SELECT COUNT(*) FROM request_logs WHERE organization_id=$1", orgB).Scan(&beforeB)
	if _, err := s.DeleteOldAuditLogs(orgA, 0); err != nil {
		t.Fatalf("DeleteOldAuditLogs: %v", err)
	}
	var afterB, afterA int
	s.db.QueryRow("SELECT COUNT(*) FROM request_logs WHERE organization_id=$1", orgB).Scan(&afterB)
	s.db.QueryRow("SELECT COUNT(*) FROM request_logs WHERE organization_id=$1", orgA).Scan(&afterA)
	if afterB != beforeB {
		t.Fatalf("delete for org A removed org B rows (%d -> %d)", beforeB, afterB)
	}
	if afterA != 0 {
		t.Fatalf("org A rows not deleted: %d", afterA)
	}
}

func TestTamperedLogBreaksIntegrity(t *testing.T) {
	s := testStore(t)
	org, _ := s.CreateOrganization("T", "sk-t")
	for i := 0; i < 3; i++ {
		s.LogRequest(RequestMetadata{Timestamp: time.Now(), RequestID: "r" + string(rune('0'+i)), Verdict: "PASS", OrganizationID: org})
	}

	if _, err := s.db.Exec(
		"UPDATE request_logs SET verdict='BLOCK' WHERE organization_id=$1 AND id = (SELECT MIN(id) FROM request_logs WHERE organization_id=$1)",
		org); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	rep, _ := s.VerifyIntegrity(org)
	if rep.Valid {
		t.Fatal("integrity check should fail after a row was edited")
	}
}

func TestBootstrapSuperAdminFromEnv(t *testing.T) {
	t.Setenv("SUPERADMIN_EMAIL", "root@test.local")
	t.Setenv("SUPERADMIN_PASSWORD", "a-really-long-password")
	s := testStore(t) // InitSchema runs bootstrapSuperAdmin

	u, err := s.GetUserByEmail("root@test.local")
	if err != nil {
		t.Fatalf("super_admin not created: %v", err)
	}
	if u.Role != "super_admin" {
		t.Fatalf("role = %q, want super_admin", u.Role)
	}
}
