package api

import (
	"cleargate/pkg/auth"
	"context"
	"os"
)

// DashboardURL is the public base URL of the admin dashboard, used to build
// links in outbound emails. Set DASHBOARD_URL in production.
var DashboardURL = getEnvDefault("DASHBOARD_URL", "http://localhost:5173")

// AllowedOrigins is the CORS allow-list. Comma-separated origins, or "*" to
// echo any origin (development only). Set CORS_ALLOWED_ORIGINS in production.
var AllowedOrigins = getEnvDefault("CORS_ALLOWED_ORIGINS", "*")

func getEnvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// contextKey is an unexported type for request-context keys, so values set by
// this package can't collide with keys from another package.
type contextKey string

const userContextKey contextKey = "user"

// UserFromContext returns the authenticated claims attached by AuthMiddleware.
func UserFromContext(ctx context.Context) (*auth.Claims, bool) {
	c, ok := ctx.Value(userContextKey).(*auth.Claims)
	return c, ok
}
