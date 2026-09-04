# ClearGate

ClearGate is an open-source security gateway for LLM traffic. It sits between
your application and OpenAI, Anthropic, or Mistral, and removes things that
should not reach a model or leave your infrastructure: emails, phone numbers,
IBANs, card numbers, API keys and other high-entropy secrets, source code, and
optionally anything semantically close to topics you have marked as forbidden.

The goal is to let a team adopt LLMs in production without waiting on a long
security review, and without relying on everyone to remember not to paste
sensitive data into a prompt.

## Features

- **PII and secret redaction.** Regex and entropy-based detection for emails,
  phones, IBANs, credit cards, API keys and tokens, and password-context
  strings. An optional Token Vault mode swaps sensitive values for reversible
  tokens instead of deleting them, so authorized responses can be rehydrated
  later.
- **Prompt injection and jailbreak heuristics.** Scores prompts for role
  manipulation, rule-conflict patterns, and pressure or secrecy language, with
  sliding-window analysis for long prompts. Can call an external classifier
  (for example Llama Guard via Ollama) for stronger detection.
- **Semantic guard (Vector Guard).** Uses Qdrant to check prompts against
  forbidden topics and an allowed-domain list, so you can block by meaning
  rather than keywords.
- **Output scanning.** The model's response is scanned as well, so a leak the
  model produces on its own is still caught.
- **Tamper-evident audit log.** Every decision is written to Postgres with a
  hash chain, so deletions or edits are detectable afterwards.
- **Per-organization policy.** Each org has its own API key and its own on/off
  switches for the checks above.
- **Admin dashboard.** A React UI for policy configuration, live traffic, audit
  logs, a request simulator, and RAG document management.

## Quick start (self-hosted)

You need Docker. Postgres, Redis, and Qdrant are started for you.

```bash
git clone https://github.com/mathisbeugnies/cleargate.git
cd cleargate
docker compose up -d
```

Create an account and get an API key in one call:

```bash
curl -X POST http://localhost:8080/api/signup \
  -H "Content-Type: application/json" \
  -d '{"org_name": "Acme Inc", "email": "you@acme.com", "password": "a-strong-password"}'
```

The response contains your `api_key` and a session `token` for the dashboard
(`cd dashboard && npm install && npm run dev`, then log in). Copy the API key;
it is only returned once.

Route your LLM calls through ClearGate instead of calling the provider directly.
You still send your own provider key in `Authorization`; ClearGate passes it
through and never stores it.

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "X-ClearGate-Key: sk-..." \
  -H "X-ClearGate-Provider: openai" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "My email is john@doe.com, summarize this ticket"}]}'
```

ClearGate strips the email before the request reaches OpenAI, logs the decision,
forwards the sanitized request, and scans the response on the way back. The path
you call is forwarded as-is to the provider (`X-ClearGate-Provider` picks the
upstream: `openai`, `anthropic`, `mistral`). Streaming (`"stream": true`) is
relayed live.

## Operations

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz` | Liveness. Always 200 while the process serves. |
| `GET /readyz` | Readiness. 200 only when the database is reachable. |
| `GET /metrics` | Prometheus metrics. Set `METRICS_TOKEN` to require a bearer token. |

Every response carries an `X-Request-ID` (echoed from the request if present).
Error bodies are JSON: `{"error": "..."}`. Per-IP rate limits on `/api/signup`
and `/auth/login` are backed by Redis when available, so they hold across
multiple instances. The full API is described in
[`docs/openapi.yaml`](./docs/openapi.yaml).

## Configuration

For production, copy the example env file and fill it in. `docker-compose.prod.yml`
reads from it:

```bash
cp .env.example .env
# set JWT_SECRET and POSTGRES_PASSWORD, then:
docker compose -f docker-compose.prod.yml up -d
```

| Variable | Purpose | Required |
| --- | --- | --- |
| `JWT_SECRET` | Signs dashboard session tokens. If unset, a random secret is generated at each restart, so sessions do not persist across restarts or across multiple instances. | Yes, in production |
| `DB_DSN` | PostgreSQL connection string | Yes |
| `CORS_ALLOWED_ORIGINS` | Comma-separated origins allowed to call the API. `*` (default) echoes any origin and is for local dev only. | Yes, in production |
| `DASHBOARD_URL` | Public dashboard URL, used in invitation email links | Yes, if using invitations |
| `SUPERADMIN_EMAIL` / `SUPERADMIN_PASSWORD` | Creates the first admin on an empty database. If unset, register via `POST /api/signup`. | No |
| `QDRANT_ADDR` | Qdrant address (for Vector Guard) | Yes |
| `REDIS_ADDR` / `REDIS_PASS` | Redis (cache and Token Vault) | Yes |
| `MAX_BODY_BYTES` | Max proxied request body size (default 10 MiB) | No |
| `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL` / `MISTRAL_BASE_URL` | Override upstream API endpoints (e.g. Azure OpenAI) | No |
| `OLLAMA_URL` | External prompt classifier (Llama Guard) | No |
| `SMTP_*` | Email delivery for teammate invitations | No |

## Project structure

```
/cmd              # Application entrypoints
  /server         # Main proxy + API server
  /decode         # Watermark decoder CLI
  /check_vector   # Vector DB debug tool
  /reset_logs     # DB maintenance tool
/dashboard        # React admin dashboard
/pkg
  /api            # REST handlers (admin, auth, signup, superadmin, vector)
  /policy         # Security policy engine
  /proxy          # Request pipeline
  /sanitizer      # PII/secret detection and the Token Vault
  /security       # Prompt injection, anomaly detection, output leak checks
  /storage        # PostgreSQL persistence and hash-chained audit log
  /vector         # Qdrant client and semantic guard
  /watermark      # Response watermarking
```

## Known limitations

This is an early project. A few things to know before relying on it for
anything critical:

- Prompt injection detection is heuristic (keyword and pattern based). It
  catches unsophisticated attempts, not a determined attacker. Point
  `OLLAMA_URL` at an external classifier for stronger coverage.
- PII detection uses regex plus a lightweight NER pass. It will miss unusual
  formats and produce occasional false positives.
- Vector Guard needs a real embedding backend to do semantic matching. Without
  one it falls back to a deterministic hash-based vector, which is closer to
  keyword matching than to meaning.
- Streaming (SSE) responses are relayed live, but the prompt is the only thing
  scanned on a streamed call; output-side redaction runs on buffered responses
  only.
- Self-serve signup (`/api/signup`) has no email verification. It is
  rate-limited per IP, but a new org and API key are created on the spot. Put
  your own gate in front if you expose it publicly.
- Test coverage is thin. Contributions welcome.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Contributions require agreeing to the
[CLA](./CLA.md) (one `git commit -s` sign-off). Security issues:
[SECURITY.md](./SECURITY.md).

## License

Source-available under the [Business Source License 1.1](./LICENSE). In short:
use it, self-host it, modify it, run it in production for free. The one thing
you can't do is offer it to third parties as a competing hosted service. Each
released version automatically converts to [Apache 2.0](./LICENSE-APACHE) four
years after its release (Change Date: 2030-09-04). For a commercial license,
contact the maintainer.
