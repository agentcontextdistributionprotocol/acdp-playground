#!/usr/bin/env bash
#
# Sync one acdp-runner Railway service's variables from Doppler, the source of truth.
#
#   deploy/doppler-sync.sh <service>                 # dry run (default): key names and changed/unchanged, never values
#   deploy/doppler-sync.sh <service> --apply         # push changed allowlisted keys from Doppler into Railway
#   deploy/doppler-sync.sh <service> --apply --no-redeploy   # set them but leave the running deployment alone
#
#   <service>   Railway service (acdp-runner)   Doppler project/config   allowlist
#   playground  acdp-playground                 acdp-playground/prd      deploy/doppler-keys/playground.txt
#   registry-a  registry-a                      acdp-registry-a/prd      deploy/doppler-keys/registry-a.txt
#   registry-b  registry-b                      acdp-registry-b/prd      deploy/doppler-keys/registry-b.txt
#
# Only the keys listed in the service's allowlist are managed. The script sets
# and updates those; it never deletes a variable, never touches a key it does
# not list, and refuses RAILWAY_* system variables and Railway references
# (values containing "${{"), which stay Railway-managed.
#
# Values move by pipe only: Doppler -> jq -> Railway GraphQL request body on
# stdin. Nothing is printed, written to disk or passed in argv; the Railway
# token reaches curl as a header file on a file descriptor, not in argv.
# Every read fails closed: a network error, a non-2xx status, an unparsable
# body, a GraphQL "errors" array or a null "data" (Railway answers a bad token
# with HTTP 200, data: null and errors) stops the run before anything is
# compared or written. The check is a
# sha256 of the sorted KEY=VALUE set of the managed keys, Doppler vs Railway.
# A redeploy happens only when at least one value actually changed.
#
# Needs git, jq, curl and the doppler CLI logged in, plus a Railway token: the
# railway CLI login (~/.railway/config.json) or RAILWAY_API_TOKEN (an account
# or workspace token; a project token cannot use these GraphQL calls).
# --apply refuses to run on a dirty tree, so the allowlist it applies is the
# committed one.
#
# Derived from acdp-registry-rs deploy/doppler-sync.sh; only the service table differs.

# Railway GraphQL queries are single-quoted on purpose.
# shellcheck disable=SC2016
set -euo pipefail

RAILWAY_PROJECT_ID=a280cc74-7393-431c-80e0-fd22ba66c4c6 # Railway: acdp-runner
RAILWAY_ENVIRONMENT=production
DOPPLER_CONFIG=prd

target="${1:-}"
case "$target" in
  playground) RAILWAY_SERVICE=acdp-playground; DOPPLER_PROJECT=acdp-playground ;;
  registry-a) RAILWAY_SERVICE=registry-a; DOPPLER_PROJECT=acdp-registry-a ;;
  registry-b) RAILWAY_SERVICE=registry-b; DOPPLER_PROJECT=acdp-registry-b ;;
  -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
  *) echo "usage: $0 <playground|registry-a|registry-b> [--apply] [--no-redeploy]" >&2; exit 2 ;;
esac
shift

mode=dry-run
redeploy=1
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) mode=dry-run ;;
    --apply) mode=apply ;;
    --no-redeploy) redeploy=0 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

say() { printf '%s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }
for c in git jq curl doppler shasum; do command -v "$c" >/dev/null || die "$c is not on PATH"; done

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(git -C "$here" rev-parse --show-toplevel)"
keys_file="$here/doppler-keys/$target.txt"
keys_name="doppler-keys/$target.txt"

if [ "$mode" = apply ] && [ -n "$(git -C "$repo" status --porcelain)" ]; then
  die "the working tree is dirty; commit or stash first so --apply uses the committed allowlist"
fi

# The allowlist: one KEY per line; '#' comments and blank lines are ignored.
keys=()
while IFS= read -r line; do
  k="${line%%#*}"
  k="$(printf '%s' "$k" | tr -d '[:space:]')"
  [ -n "$k" ] || continue
  [[ "$k" =~ ^[A-Z_][A-Z0-9_]*$ ]] || die "$keys_name: '$k' is not a valid variable name"
  [[ "$k" == RAILWAY_* ]] && die "$keys_name: $k is a Railway system variable; Railway owns it"
  keys+=("$k")
done <"$keys_file"
[ "${#keys[@]}" -gt 0 ] || die "$keys_file lists no keys"
keys_json="$(printf '%s\n' "${keys[@]}" | jq -R . | jq -sc 'unique')"

railway_token="${RAILWAY_API_TOKEN:-$(jq -r '.user.accessToken // .user.token // empty' ~/.railway/config.json 2>/dev/null || true)}"
[ -n "$railway_token" ] || die "no Railway token: log in with the railway CLI or set RAILWAY_API_TOKEN"

# POST a GraphQL request whose JSON body arrives on stdin, so values never reach
# argv; the token goes in as a header file on a descriptor (printf is a builtin,
# so it never shows in ps). Prints .data on success. Returns non-zero, saying
# why, on a network error, a non-2xx status, an unparsable body, a non-empty
# "errors" or a null/missing "data". Callers must check the status: set -e does
# not apply inside a function called from a || list.
railway_gql() {
  local resp code body
  resp="$(curl -sS --max-time 60 -w '\n%{http_code}' https://backboard.railway.com/graphql/v2 \
    -H @<(printf 'Authorization: Bearer %s\n' "$railway_token") \
    -H 'content-type: application/json' --data-binary @-)" || {
    say "railway: request failed (network)"
    return 1
  }
  code="${resp##*$'\n'}"
  body="${resp%$'\n'*}"
  [[ "$code" =~ ^2[0-9][0-9]$ ]] || {
    say "railway: HTTP $code"
    return 1
  }
  jq -e 'if type != "object" then error("railway: response is not a JSON object")
    elif ((.errors // []) | length) > 0 then error("railway: \(.errors | map(.message // "?") | join("; "))")
    elif .data == null then error("railway: response has no data")
    else .data end' <<<"$body" || {
    say "railway: unusable response (HTTP $code)"
    return 1
  }
}
gql() { jq -nc --arg q "$1" --argjson v "${2:-{\}}" '{query: $q, variables: $v}' | railway_gql; }

ids="$(gql 'query($p: String!){project(id: $p){environments{edges{node{id name}}} services{edges{node{id name}}}}}' \
  "$(jq -nc --arg p "$RAILWAY_PROJECT_ID" '{p: $p}')")" || die "reading the Railway project failed; nothing changed"
env_id="$(jq -r --arg n "$RAILWAY_ENVIRONMENT" '.project.environments.edges[].node | select(.name == $n) | .id' <<<"$ids")" ||
  die "unexpected Railway project shape; nothing changed"
svc_id="$(jq -r --arg n "$RAILWAY_SERVICE" '.project.services.edges[].node | select(.name == $n) | .id' <<<"$ids")" ||
  die "unexpected Railway project shape; nothing changed"
[ -n "$env_id" ] || die "Railway environment $RAILWAY_ENVIRONMENT not found in project $RAILWAY_PROJECT_ID"
[ -n "$svc_id" ] || die "Railway service $RAILWAY_SERVICE not found in project $RAILWAY_PROJECT_ID"
scope="$(jq -nc --arg p "$RAILWAY_PROJECT_ID" --arg e "$env_id" --arg s "$svc_id" '{p: $p, e: $e, s: $s}')"

# Raw (unrendered) service variables, so a reference shows up as ${{...}}, not its resolved value.
railway_vars() {
  gql 'query($p: String!, $e: String!, $s: String!){variables(projectId: $p, environmentId: $e, serviceId: $s, unrendered: true)}' \
    "$scope" | jq -ec '.variables | if type == "object" then . else error("railway: variables is not an object") end'
}
# The values stay in the pipe; jq only checks the shape (it never echoes the input).
doppler_vars() {
  doppler secrets download --project "$DOPPLER_PROJECT" --config "$DOPPLER_CONFIG" --no-file --format json |
    jq -ec 'if type == "object" then . else error("doppler: download is not a JSON object") end'
}

# sha256 of the sorted KEY=VALUE lines of the managed keys (a missing key hashes as absent).
managed_hash() {
  jq -r --argjson k "$keys_json" '. as $v | $k[] as $key | select($v | has($key)) | "\($key)=\($v[$key])"' | LC_ALL=C sort | shasum -a 256 | cut -c1-16
}

rv="$(railway_vars)" || die "reading Railway variables for $RAILWAY_SERVICE failed; nothing changed"
dv="$(doppler_vars)" || die "reading Doppler $DOPPLER_PROJECT/$DOPPLER_CONFIG failed; nothing changed"

# Per key: status only. The comparison happens inside jq; values never leave it.
plan="$(printf '%s\n%s\n' "$dv" "$rv" | jq -sc --argjson k "$keys_json" '
  .[0] as $d | .[1] as $r |
  [$k[] | . as $key | {key: $key, status: (
    if ($d | has($key) | not) then "missing-in-doppler"
    elif ($d[$key] | tostring | contains("${{")) then "doppler-value-is-a-reference"
    elif ($r | has($key)) and ($r[$key] | contains("${{")) then "railway-reference"
    elif ($r | has($key) | not) then "new"
    elif $r[$key] == $d[$key] then "unchanged"
    else "changed" end)}]')" || die "comparing Doppler with Railway failed; nothing changed"

say "Doppler $DOPPLER_PROJECT/$DOPPLER_CONFIG -> Railway $RAILWAY_SERVICE ($RAILWAY_ENVIRONMENT), ${#keys[@]} managed key(s):"
jq -r '.[] | "  \(.key)\t\(.status)"' <<<"$plan" >&2
unmanaged="$(jq -r --argjson k "$keys_json" 'keys - $k | join(" ")' <<<"$rv")"
[ -z "$unmanaged" ] || say "  left alone (not in $keys_name): $unmanaged"

bad="$(jq -r '[.[] | select(.status | IN("missing-in-doppler", "doppler-value-is-a-reference", "railway-reference")) | .key] | join(" ")' <<<"$plan")"
[ -z "$bad" ] || die "refusing: $bad (see status above; a Railway reference must stay Railway-managed, so drop it from $keys_name)"
todo="$(jq -r '.[] | select(.status | IN("new", "changed")) | .key' <<<"$plan")"

before="$(managed_hash <<<"$rv")" || die "hashing failed; nothing changed"
want="$(managed_hash <<<"$dv")" || die "hashing failed; nothing changed"
say "hash: railway $before, doppler $want ($([ "$before" = "$want" ] && echo match || echo differ))"

if [ "$mode" = dry-run ]; then
  if [ -n "$todo" ]; then say "dry run: $(wc -w <<<"$todo" | tr -d ' ') key(s) would change; rerun with --apply"; else say "dry run: nothing to change"; fi
  exit 0
fi

if [ -z "$todo" ]; then
  say "apply: nothing to change; no redeploy"
  exit 0
fi

done_keys=()
for key in $todo; do
  # The value goes Doppler -> jq -> curl stdin; it is never in argv or on disk.
  doppler_vars | jq -c --arg key "$key" --argjson s "$scope" '{
      query: "mutation($i: VariableUpsertInput!){variableUpsert(input: $i)}",
      variables: {i: {projectId: $s.p, environmentId: $s.e, serviceId: $s.s, name: $key, value: .[$key], skipDeploys: true}}}' |
    railway_gql >/dev/null ||
    die "setting $key failed; set before it: ${done_keys[*]:-none}; no redeploy"
  done_keys+=("$key")
  say "  set $key"
done

after_vars="$(railway_vars)" || die "re-reading Railway variables failed after apply; no redeploy"
after="$(managed_hash <<<"$after_vars")" || die "hashing failed after apply; no redeploy"
[ "$after" = "$want" ] || die "hash after apply is $after, expected $want; check the service in Railway"
say "hash after apply: $after (match)"

if [ "$redeploy" = 1 ]; then
  gql 'mutation($e: String!, $s: String!){serviceInstanceRedeploy(environmentId: $e, serviceId: $s)}' "$scope" >/dev/null ||
    die "values are set (hash matches) but the redeploy request failed; redeploy $RAILWAY_SERVICE by hand"
  say "redeploy triggered for $RAILWAY_SERVICE so the new values take effect"
else
  say "no redeploy (--no-redeploy): the values apply on the next deploy"
fi
