package provider

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPProviderForwardsRequest(t *testing.T) {
	var gotPath, gotMethod, gotAuth, gotBody, gotCG string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotCG = r.Header.Get("X-ClearGate-Key")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	p := &httpProvider{name: "Test", baseURL: upstream.URL, defaultPath: "/v1/chat/completions"}

	in := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"x"}`))
	in.Header.Set("Authorization", "Bearer sk-caller")
	in.Header.Set("X-ClearGate-Key", "sk-cleargate-secret")
	in.Header.Set("Content-Type", "application/json")

	resp, err := p.SendRequest(in)
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}
	defer resp.Body.Close()

	if gotMethod != http.MethodPost || gotPath != "/v1/chat/completions" {
		t.Fatalf("upstream got %s %s", gotMethod, gotPath)
	}
	if gotBody != `{"model":"x"}` {
		t.Fatalf("body not forwarded: %q", gotBody)
	}
	if gotAuth != "Bearer sk-caller" {
		t.Fatalf("caller Authorization not forwarded: %q", gotAuth)
	}
	if gotCG != "" {
		t.Fatalf("X-ClearGate-* header leaked upstream: %q", gotCG)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestHTTPProviderDefaultsPath(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	}))
	defer upstream.Close()

	p := &httpProvider{name: "Test", baseURL: upstream.URL, defaultPath: "/v1/messages"}
	in := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	if _, err := p.SendRequest(in); err != nil {
		t.Fatalf("SendRequest: %v", err)
	}
	if gotPath != "/v1/messages" {
		t.Fatalf("expected default path, got %q", gotPath)
	}
}
