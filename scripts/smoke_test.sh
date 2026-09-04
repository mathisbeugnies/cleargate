#!/usr/bin/env bash
# End-to-end smoke test. Run after: docker compose up -d
# Usage: BASE=http://localhost:8080 OPENAI_API_KEY=sk-... ./scripts/smoke_test.sh
set -euo pipefail

BASE="${BASE:-http://localhost:8080}"
pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; exit 1; }

echo "1. Signup"
RESP=$(curl -s -X POST "$BASE/api/signup" -H 'Content-Type: application/json' \
  -d "{\"org_name\":\"Smoke Inc\",\"email\":\"smoke+$(date +%s)@example.com\",\"password\":\"a-strong-password\"}")
API_KEY=$(echo "$RESP" | sed -n 's/.*"api_key":"\([^"]*\)".*/\1/p')
TOKEN=$(echo "$RESP" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$API_KEY" ] && [ -n "$TOKEN" ] && pass "got api_key + token" || fail "signup response: $RESP"

echo "2. Signup rejects reserved local-part"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/signup" -H 'Content-Type: application/json' \
  -d '{"org_name":"x","email":"admin@example.com","password":"a-strong-password"}')
[ "$CODE" = "403" ] && pass "admin@ blocked (403)" || fail "expected 403, got $CODE"

echo "3. Signup rate limit (6 rapid calls -> 429)"
LAST=""
for i in $(seq 1 6); do
  LAST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/signup" -H 'Content-Type: application/json' \
    -d '{"org_name":"rl","email":"rl@example.com","password":"a-strong-password"}')
done
[ "$LAST" = "429" ] && pass "rate limited (429)" || fail "expected 429, got $LAST"

echo "4. Authenticated config read"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/config" -H "Authorization: Bearer $TOKEN")
[ "$CODE" = "200" ] && pass "GET /api/config (200)" || fail "expected 200, got $CODE"

echo "5. Config read without token -> 401"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/config")
[ "$CODE" = "401" ] && pass "unauth rejected (401)" || fail "expected 401, got $CODE"

echo "6. Security headers present"
H=$(curl -s -D - -o /dev/null "$BASE/api/config")
echo "$H" | grep -qi '^x-content-type-options: nosniff' && pass "X-Content-Type-Options" || fail "missing nosniff"
echo "$H" | grep -qi '^content-security-policy:' && pass "Content-Security-Policy" || fail "missing CSP"

echo "7. Proxy rejects missing API key"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/v1/chat/completions" -d '{}')
[ "$CODE" = "401" ] && pass "no key -> 401" || fail "expected 401, got $CODE"

echo "8. Proxy request (needs OPENAI_API_KEY; strips PII before forwarding)"
if [ -n "${OPENAI_API_KEY:-}" ]; then
  OUT=$(curl -s -X POST "$BASE/v1/chat/completions" \
    -H "X-ClearGate-Key: $API_KEY" -H 'X-ClearGate-Provider: openai' \
    -H "Authorization: Bearer $OPENAI_API_KEY" -H 'Content-Type: application/json' \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"My email is leak@doe.com. Reply OK."}]}')
  echo "$OUT" | grep -q 'leak@doe.com' && fail "email leaked to provider echo!" || pass "email not present in response"
else
  echo "  SKIP  set OPENAI_API_KEY to exercise a real upstream call"
fi

echo
echo "All checks passed."
