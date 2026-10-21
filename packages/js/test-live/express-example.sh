#!/usr/bin/env bash
# Live smoke test: examples/express-app against a real Identvia. Usage: IDENTVIA_LIVE_STATE=/tmp/live-state.json test-live/express-example.sh
set -euo pipefail
S=${IDENTVIA_LIVE_STATE:?}
HERE=$(cd "$(dirname "$0")" && pwd)
HELPER="$HERE/../../../../tools/live/helper.php"
j() { php -r "echo json_decode(file_get_contents('$S'), true)['$1'];"; }
JAR=$(mktemp); PASS=0; FAIL=0
check() { if [ "$2" = "1" ]; then PASS=$((PASS+1)); echo "  PASS $1"; else FAIL=$((FAIL+1)); echo "  FAIL $1 [$3]"; fi; }
cd "$HERE/../../../examples/express-app"
IDENTVIA_ISSUER=$(j base) IDENTVIA_CLIENT_ID=$(j confClientId) IDENTVIA_CLIENT_SECRET=$(j confSecret) SESSION_SECRET=live-express-secret-0123456789abcdefghijk node server.mjs > /tmp/express-example.log 2>&1 &
PID=$!; trap 'kill $PID' EXIT; sleep 1
B=http://localhost:4301
r=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Accept: text/html' $B/account); check "/account redirects to login when signed out" $([[ "$r" == "302 $B/auth/login?returnTo=%2Faccount" ]] && echo 1) "$r"
loc=$(curl -s -c $JAR -b $JAR -o /dev/null -w '%{redirect_url}' "$B/auth/login?returnTo=/account")
check "login redirects to Identvia authorize" $([[ "$loc" == "$(j base)/oauth/authorize?"* ]] && echo 1) "$loc"
cb=$(php "$HELPER" browse "$S" "$loc")
r=$(curl -s -c $JAR -b $JAR -o /dev/null -w '%{http_code} %{redirect_url}' "$cb")
check "callback signs in and returns to /account" $([[ "$r" == "302 $B/account" ]] && echo 1) "$r"
body=$(curl -s -b $JAR -c $JAR $B/api/me)
check "/api/me returns the user" $(echo "$body" | grep -q "$(j userEmail)" && echo 1) "$body"
r=$(curl -s -b $JAR -c $JAR -o /dev/null -w '%{http_code}' -X POST -H "Origin: https://evil.example" $B/auth/logout)
check "cross-site logout blocked" $([[ "$r" == "403" ]] && echo 1) "$r"
r=$(curl -s -b $JAR -c $JAR -o /dev/null -w '%{http_code}' -X POST -H "Origin: $B" $B/auth/logout)
check "logout" $([[ "$r" == "303" ]] && echo 1) "$r"
r=$(curl -s -b $JAR -o /dev/null -w '%{http_code}' -H 'Accept: application/json' $B/api/me)
check "signed out afterwards" $([[ "$r" == "401" ]] && echo 1) "$r"
echo; echo "$PASS passed, $FAIL failed"; [ $FAIL -eq 0 ]
