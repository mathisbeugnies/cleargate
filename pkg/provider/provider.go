package provider

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Provider forwards an already-sanitized request to an upstream LLM API.
type Provider interface {
	Name() string
	SendRequest(r *http.Request) (*http.Response, error)
}

// sharedClient is reused across providers. The timeout is generous because
// completions can be slow. The transport keeps a pool of connections per
// upstream host since a proxy talks to only a handful of them.
var sharedClient = &http.Client{
	Timeout: 120 * time.Second,
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	},
}

// hopByHop headers must not be forwarded to the upstream.
var hopByHop = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// httpProvider is the shared implementation. The caller supplies its own
// upstream credentials (Authorization / x-api-key headers), which are passed
// through unchanged; ClearGate never stores provider keys.
type httpProvider struct {
	name        string
	baseURL     string
	defaultPath string
	// defaultHeaders are added only when the caller didn't set them.
	defaultHeaders map[string]string
}

func newHTTPProvider(name, envKey, defaultBase, defaultPath string) *httpProvider {
	base := strings.TrimRight(os.Getenv(envKey), "/")
	if base == "" {
		base = defaultBase
	}
	return &httpProvider{name: name, baseURL: base, defaultPath: defaultPath}
}

func (p *httpProvider) Name() string { return p.name }

func (p *httpProvider) SendRequest(r *http.Request) (*http.Response, error) {
	path := r.URL.Path
	if path == "" || path == "/" {
		path = p.defaultPath
	}
	target := p.baseURL + path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	out, err := http.NewRequestWithContext(r.Context(), r.Method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	for name, values := range r.Header {
		lower := strings.ToLower(name)
		if hopByHop[lower] || lower == "host" || lower == "content-length" || strings.HasPrefix(lower, "x-cleargate-") {
			continue
		}
		for _, v := range values {
			out.Header.Add(name, v)
		}
	}
	for k, v := range p.defaultHeaders {
		if out.Header.Get(k) == "" {
			out.Header.Set(k, v)
		}
	}
	out.ContentLength = int64(len(body))

	log.Debug().Str("provider", p.name).Str("target", target).Msg("Forwarding request upstream")
	return sharedClient.Do(out)
}
