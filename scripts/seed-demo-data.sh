#!/usr/bin/env bash
# Populate cert-inventory / iam-accounts / audit-hot with demo rows so the UI has
# enough data to exercise every control and colour band.
#
#   ./scripts/seed-demo-data.sh                          # defaults (40/15/30)
#   ./scripts/seed-demo-data.sh --certs 200 --accounts 50
#   ./scripts/seed-demo-data.sh --clean                  # remove them again
#
# OWNERSHIP IS THE WHOLE TRICK. GET /certs and GET /iam/accounts query
# OwnerIndex with the caller's Cognito `sub`, so a row is visible to exactly one
# login. Set SEED_OWNER_ID to your own sub:
#
#   SEED_OWNER_ID=<your-sub> ./scripts/seed-demo-data.sh
#
# Find it by signing in once and reading any api-certs-fn log line's `ownerId`
# field, or from the Cognito console. It is also in the JWT — the `sub` claim.
#
# Every id starts with `demo-`, and --clean deletes only those ids, so this can
# never remove a genuinely discovered certificate or account.
set -euo pipefail

cd "$(dirname "$0")/.."

REGION="${REGION:-ap-southeast-1}"
CERT_TABLE="app-d9fae51c-1929cc69-cert-inventory"
IAM_TABLE="app-d9fae51c-1929cc69-iam-accounts"
AUDIT_TABLE="app-d9fae51c-1929cc69-audit-hot"

# Same default as deploy.sh, so a plain run seeds the same login either way.
SEED_OWNER_ID="${SEED_OWNER_ID:-d9ca551c-d0a1-7011-1c4f-99a48c8d917f}"

CERTS=40
ACCOUNTS=15
AUDIT_EVENTS=30
CLEAN=false

while [ $# -gt 0 ]; do
  case "$1" in
    --certs)        CERTS="$2"; shift 2 ;;
    --accounts)     ACCOUNTS="$2"; shift 2 ;;
    --audit-events) AUDIT_EVENTS="$2"; shift 2 ;;
    --owner-id)     SEED_OWNER_ID="$2"; shift 2 ;;
    --clean)        CLEAN=true; shift ;;
    -h|--help)      sed -n '2,20p' "$0"; exit 0 ;;
    *)              echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

pass() { printf '  \033[32m+\033[0m  %s\n' "$1"; }
info() { printf '     %s\n' "$1"; }
die()  { printf '\033[31merror\033[0m %s\n' "$1" >&2; exit 1; }

OUT_DIR="$(mktemp -d)"
trap 'rm -rf "$OUT_DIR"' EXIT

GEN_ARGS=(
  --owner-id "$SEED_OWNER_ID"
  --certs "$CERTS" --accounts "$ACCOUNTS" --audit-events "$AUDIT_EVENTS"
  --cert-table "$CERT_TABLE" --iam-table "$IAM_TABLE" --audit-table "$AUDIT_TABLE"
  --out-dir "$OUT_DIR"
)
[ "$CLEAN" = true ] && GEN_ARGS+=(--delete)

if [ "$CLEAN" = true ]; then
  printf '\n\033[1mRemoving demo rows owned by %s\033[0m\n' "$SEED_OWNER_ID"
else
  printf '\n\033[1mSeeding %s certificates, %s accounts, %s audit events\033[0m\n' \
    "$CERTS" "$ACCOUNTS" "$AUDIT_EVENTS"
  info "owner: $SEED_OWNER_ID"
fi

BATCHES="$(python3 scripts/gen_demo_data.py "${GEN_ARGS[@]}")"
[ -n "$BATCHES" ] || die "generator produced no batches"

# BatchWriteItem reports per-item throttling in UnprocessedItems rather than
# failing the call, so a batch that "succeeded" can still have written nothing.
# Feed those straight back in; PAY_PER_REQUEST tables rarely need more than one
# extra pass.
apply_batch() {
  local file="$1" attempt=1
  while [ "$attempt" -le 5 ]; do
    local response
    response="$(aws dynamodb batch-write-item \
      --request-items "file://${file}" --region "$REGION" --output json)" \
      || die "batch-write-item failed for $file
       If this is AccessDenied, your own credentials cannot write these tables —
       run ./deploy.sh instead, which seeds under the deploy role."

    local unprocessed
    unprocessed="$(printf '%s' "$response" | python3 -c "
import json, sys
data = json.load(sys.stdin).get('UnprocessedItems') or {}
print(json.dumps(data) if data else '')
")"
    [ -n "$unprocessed" ] || return 0

    printf '%s' "$unprocessed" > "$file"
    attempt=$((attempt + 1))
    sleep $((attempt))
  done
  die "items still unprocessed after 5 attempts for $file"
}

COUNT=0
while IFS= read -r file; do
  apply_batch "$file"
  COUNT=$((COUNT + 1))
done <<<"$BATCHES"

pass "applied $COUNT batch(es)"

if [ "$CLEAN" = true ]; then
  printf '\n\033[32mDemo rows removed.\033[0m\n'
  exit 0
fi

cat <<EOF

$(printf '\033[32mDone.\033[0m') Sign in as the owner of $SEED_OWNER_ID and check:

  Certificates   $CERTS rows spanning all three colour bands (red <=7d,
                 amber <=30d, green beyond). ~1 in 6 carries a non-ISSUED
                 status, so it is excluded from expiry alerting on purpose.
  IAM Accounts   $ACCOUNTS rows. ~1 in 4 is warning/critical rather than active.
  Audit          search for  $SEED_OWNER_ID  to see $AUDIT_EVENTS events.

Remove them again with:
  SEED_OWNER_ID=$SEED_OWNER_ID ./scripts/seed-demo-data.sh --clean
EOF
