package api

import "testing"

func TestReservedLocalPart(t *testing.T) {
	reserved := []string{
		"admin@acme.com",
		"Admin@acme.com",
		"  root@acme.com",
		"superadmin@example.org",
		"postmaster@x.io",
	}
	for _, e := range reserved {
		if !reservedLocalPart(e) {
			t.Errorf("%q should be reserved", e)
		}
	}

	ok := []string{"alice@acme.com", "admin.jones@acme.com", "notanemail", "team-admin@acme.com"}
	for _, e := range ok {
		if reservedLocalPart(e) {
			t.Errorf("%q should be allowed", e)
		}
	}
}
