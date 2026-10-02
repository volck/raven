#!/usr/bin/env bash
# Non-destructive checks for a freshly deployed flock-wrangler.
#
# A real provision (phases 4-5) is deliberately not automated: it creates a
# Vault engine, a Bitbucket repository and a git branch that must all be
# cleaned up by hand.
#
#   WRANGLER_TOKEN=... scripts/verify-wrangler.sh
set -uo pipefail

NS=${WRANGLER_NAMESPACE:-ssg}
NAME=${WRANGLER_SMOKE_NAME:-wrangler-smoke}
URL=${WRANGLER_URL:-}

fail=0
check() {
	if [[ "$2" == "$3" ]]; then
		printf 'PASS  %-40s %s\n' "$1" "$3"
	else
		printf 'FAIL  %-40s got %s, want %s\n' "$1" "$3" "$2"
		fail=1
	fi
}
status() { curl -sk -o /dev/null -w '%{http_code}' "$@"; }

echo "== phase 0: rollout =="
oc -n "$NS" rollout status deploy/flock-wrangler --timeout=60s || fail=1
if [[ -z $URL ]]; then
	host=$(oc -n "$NS" get route flock-wrangler -o jsonpath='{.spec.host}' 2>/dev/null)
	[[ -n $host ]] || { echo "no route flock-wrangler in $NS; set WRANGLER_URL"; exit 1; }
	URL="https://$host"
fi
echo "url: $URL"

echo
echo "== phase 0: health =="
check "GET /healthz" 200 "$(status "$URL/healthz")"

echo
echo "== phase 1: auth gate =="
check "POST /api/v1/ravens (no token)" 401 \
	"$(status -X POST -H 'Content-Type: application/json' -d '{}' "$URL/api/v1/ravens")"

echo
echo "== phase 2: read paths =="
check "GET /api/v1/rollouts" 200 "$(status "$URL/api/v1/rollouts")"
echo "-- ravens labelled managedBy=flock-wrangler (the backfill) --"
oc -n "$NS" get deploy -l managedBy=flock-wrangler --no-headers 2>/dev/null | awk '{print "   " $1}' ||
	echo "   (none)"

if [[ -z ${WRANGLER_TOKEN:-} ]]; then
	echo
	echo "SKIP  phases 1b/3: set WRANGLER_TOKEN to a token with scope raven:provision"
	exit $fail
fi

echo
echo "== phase 3: preflight rejection =="
# Only meaningful while the ServiceAccount is absent: that is what preflight
# is expected to complain about.
if oc -n "$NS" get sa "$NAME-cleaner" >/dev/null 2>&1; then
	echo "WARN  serviceaccount $NAME-cleaner exists; a POST here would really provision."
	exit $fail
fi

body=$(
	cat <<EOF
{"name":"$NAME","secretEngine":"${NAME//-/}","destEnv":"${NAME//-/}",
 "repoURL":"ssh://git@bitbucket.norsk-tipping.no:7999/sec/sealedsecrets-${NAME//-/}.git"}
EOF
)
out=$(curl -sk -w '\n%{http_code}' -X POST \
	-H "Authorization: Bearer $WRANGLER_TOKEN" \
	-H 'Content-Type: application/json' \
	-d "$body" "$URL/api/v1/ravens")
code=${out##*$'\n'}
check "POST /api/v1/ravens (missing prereqs)" 409 "$code"
echo "-- response --"
echo "${out%$'\n'*}" | head -20

exit $fail
