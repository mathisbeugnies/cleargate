# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.0] - 2026-09-04

First public release.

### Added
- **Self-serve signup**: `POST /api/signup` creates an organization, its API
  key and a first `org_admin` in one call, rate-limited per IP. Dashboard
  signup page and `/signup` route.
- **Cookie-based dashboard sessions.** Login and signup set an httpOnly,
  SameSite=Lax `cleargate_session` cookie (Secure when served over TLS). The
  dashboard keeps no JWT in `localStorage`, so an XSS can't steal the session.
  `GET /auth/me` and `POST /auth/logout` added; the Authorization bearer header
  still works for API/CLI clients.
- Panic-recovery middleware: a handler panic returns a JSON 500 instead of a
  dropped connection.
- Redis-backed per-IP rate limiting on `/api/signup` and `/auth/login`, shared
  across instances (in-memory fallback when Redis is down; fails open).
- `X-Request-ID` request/response header.
- `docs/openapi.yaml`: OpenAPI 3.1 description of the API.
- Anthropic provider sends a default `anthropic-version` header when omitted.
- **Real provider forwarding** to OpenAI, Anthropic and Mistral (override with
  `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL` / `MISTRAL_BASE_URL`). The caller's
  own provider key is passed through and never stored.
- **Streaming**: `"stream": true` / SSE responses are relayed to the client
  chunk by chunk.
- **Operational endpoints**: `GET /healthz`, `GET /readyz` (DB ping),
  `GET /metrics` (Prometheus; gate with `METRICS_TOKEN`). Docker `HEALTHCHECK`.
- Per-IP rate limiting on `/api/signup` and `/auth/login`.
- CORS allow-list (`CORS_ALLOWED_ORIGINS`) and security-header middleware
  (CSP, `X-Frame-Options`, `nosniff`, `Referrer-Policy`, HSTS on TLS).
- CI: build, vet, `go test` (incl. Postgres-backed storage tests), staticcheck,
  govulncheck, dashboard lint + build, Docker image build with a Trivy scan,
  and a DCO sign-off check on pull requests.

### Changed
- **License**: relicensed from Apache-2.0 to the Business Source License 1.1
  (Change Date 2030-09-04, Change License Apache-2.0). Contributions now
  require a DCO sign-off and CLA acceptance.
- JWT session tokens are validated as HS256 only, live 8 hours, and carry
  `nbf`. Login runs a constant-time-ish comparison for unknown accounts.
- The first `super_admin` is created only from `SUPERADMIN_EMAIL` /
  `SUPERADMIN_PASSWORD` on an empty database. Removed the seed that promoted a
  well-known address.
- API keys are stored as SHA-256 and never returned after creation.
- Audit-log deletion and integrity verification are scoped to the caller's
  organization; the hash chain is per-org and serialized with a per-org
  advisory lock instead of `LOCK TABLE` on every request.
- `/api/admin/reload` is `super_admin` only.
- Proxy request and buffered response bodies are capped (`MAX_BODY_BYTES`,
  default 10 MiB).
- `storage.NewStore` retries the database connection for up to 30 s; the app
  no longer crashes when it starts before Postgres is ready.
- Go toolchain 1.26; bumped grpc, `golang.org/x/net`, `/x/text`, `/x/crypto`,
  protobuf. `govulncheck` is clean.
- Phone detection also matches E.164 international and national numbers with a
  leading trunk zero (FR/UK/DE), not just US 3-3-4.
- Backend `Dockerfile` fixed (it did not build); non-root runtime user,
  static binary, module-download layer caching. `.dockerignore` added.
- README rewritten; `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `CLA.md`, `.env.example`, issue/PR templates added.
- API and proxy error responses are JSON (`{"error": "..."}`) instead of plain
  text.

### Fixed
- `/api/stats` panicked (nil `PointsCount` from Qdrant) and dropped the
  connection; now returns 0 when the count is absent.

### Security
- Removed the hardcoded JWT signing key (`JWT_SECRET`, random per-process
  fallback).
- Removed a privilege-escalation path where signing up as a fixed email became
  `super_admin` on the next restart.
- Stopped logging full API keys and bootstrap passwords.
- Strip CR/LF from SMTP header inputs (invitation email).

[Unreleased]: https://github.com/mathisbeugnies/cleargate/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mathisbeugnies/cleargate/releases/tag/v0.1.0
