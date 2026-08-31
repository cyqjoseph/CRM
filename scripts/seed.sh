#!/usr/bin/env bash
# Seeds demo certificates, IAM accounts and audit events owned by a real login,
# so the UI has something to show and every control can be exercised.
#
#   ./scripts/seed.sh you@example.com            # create the rows
#   ./scripts/seed.sh you@example.com --clean    # remove them again
#
# WHY THIS IS NEEDED, and not just a convenience:
#
# Every read endpoint is owner-scoped. GET /certs and GET /iam/accounts query
# OwnerIndex with `OwnerId = <the caller's Cognito sub>`. Discovery derives
# OwnerId from an ACM domain name, an IAM server-certificate path, or a
# `crm:owner-id` tag — never from a Cognito sub. So rows written by a completely
# healthy discovery run belong to no human login and appear in nobody's UI. An
# empty Certificates tab is therefore the expected state on a fresh account and
# tells you nothing about whether the pipeline works.
#
# Seeding rows against your own sub is what makes the UI, the owner scoping, the
# GSI queries and the renew/rotate actions observable end to end.
#
# Safe by construction: every id it writes starts with `seed-`, and --clean
# deletes only those ids, so it can never remove a genuinely discovered
# certificate.
set -euo pipefail

cd "$(dirname "$0")/.."

REGION="${REGION:-ap-southeast-1}"
CERT_TABLE="app-d9fae51c-1929cc69-cert-inventory"
IAM_TABLE="app-d9fae51c-1929cc69-iam-accounts"
AUDIT_TABLE="app-d9fae51c-1929cc69-audit-hot"

# shellcheck source=scripts/lib-stack-outputs.sh
source scripts/lib-stack-outputs.sh

pass() { printf '  \033[32m+\033[0m  %s\n' "$1"; }
info() { printf '     %s\n' "$1"; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }
die()  { printf '\033[31merror\033[0m %s\n' "$1" >&2; exit 1; }

TARGET_EMAIL=""
CLEAN=false
for arg in "$@"; do
  case "$arg" in
    --clean) CLEAN=true ;;
    -*)      die "unknown flag: $arg" ;;
    *)       TARGET_EMAIL="$arg" ;;
  esac
done

[ -n "$TARGET_EMAIL" ] || die "usage: ./scripts/seed.sh <email> [--clean]
       The email must be a user in the Cognito pool — sign up in the app first.
       Its Cognito 'sub' becomes the OwnerId on every seeded row, which is what
       makes the rows visible to that login and nobody else."

step "Resolving the target user"
info "outputs from: $OUTPUTS_SOURCE"

# The sub is the whole point: it is the OwnerId the API queries OwnerIndex with.
USER_SUB="$(aws cognito-idp admin-get-user \
  --user-pool-id "$USER_POOL_ID" --username "$TARGET_EMAIL" --region "$REGION" \
  --query "UserAttributes[?Name=='sub'].Value | [0]" --output text 2>/dev/null || echo "")"

if [ -z "$USER_SUB" ] || [ "$USER_SUB" = "None" ]; then
  die "$TARGET_EMAIL is not a confirmed user in $USER_POOL_ID.
       Sign up at $APP_URL and verify the email first, then re-run."
fi
pass "$TARGET_EMAIL -> sub $USER_SUB"

# --- Fixtures -----------------------------------------------------------------
# Expiry offsets deliberately span all three bands the UI colours, so seeding
# exercises the rendering and not just the query:
#   <= 7 days  -> status-danger    <= 30 days -> status-warn    else status-ok
# The IAM rotation rows likewise span imminent and distant.
#
# id|domain|days-until-expiry|status
SEED_CERTS=(
  "seed-cert-expiring-now|payments.internal.example.com|3|ISSUED"
  "seed-cert-expiring-soon|sso.internal.example.com|14|ISSUED"
  "seed-cert-expiring-month|api.internal.example.com|28|ISSUED"
  "seed-cert-healthy|www.example.com|75|ISSUED"
  "seed-cert-long-lived|vpn.example.com|240|ISSUED"
)

# id|days-until-next-rotation|status
SEED_IAM_ACCOUNTS=(
  "seed-iam-svc-payments|4|warning"
  "seed-iam-svc-reporting|21|active"
  "seed-iam-svc-backup|88|active"
)

_date_in_days() {
  python3 -c "
import datetime, sys
days = int(sys.argv[1])
print((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)).date().isoformat())
" "$1"
}

# --- Clean --------------------------------------------------------------------
if [ "$CLEAN" = true ]; then
  step "Removing seeded rows"

  for row in "${SEED_CERTS[@]}"; do
    IFS='|' read -r cert_id _ _ _ <<<"$row"
    aws dynamodb delete-item --table-name "$CERT_TABLE" --region "$REGION" \
      --key "{\"CertId\": {\"S\": \"$cert_id\"}}"
    pass "deleted $cert_id"
  done

  for row in "${SEED_IAM_ACCOUNTS[@]}"; do
    IFS='|' read -r account_hash _ _ <<<"$row"
    aws dynamodb delete-item --table-name "$IAM_TABLE" --region "$REGION" \
      --key "{\"AccountIdHash\": {\"S\": \"$account_hash\"}}"
    pass "deleted $account_hash"
  done

  # Audit rows are append-only by design, so they are queried and deleted by key
  # rather than assumed. EntityId is the sub; the range key is EventTimestamp.
  TIMESTAMPS="$(aws dynamodb query --table-name "$AUDIT_TABLE" --region "$REGION" \
    --key-condition-expression "EntityId = :e" \
    --expression-attribute-values "{\":e\": {\"S\": \"$USER_SUB\"}}" \
    --query "Items[?starts_with(Actor.S, 'seed.sh')].EventTimestamp.S" \
    --output text 2>/dev/null || echo "")"

  for ts in $TIMESTAMPS; do
    aws dynamodb delete-item --table-name "$AUDIT_TABLE" --region "$REGION" \
      --key "{\"EntityId\": {\"S\": \"$USER_SUB\"}, \"EventTimestamp\": {\"S\": \"$ts\"}}"
    pass "deleted audit event $ts"
  done

  printf '\n\033[32mSeed data removed.\033[0m\n'
  exit 0
fi

# --- Seed certificates --------------------------------------------------------
step "Seeding certificates into $CERT_TABLE"
for row in "${SEED_CERTS[@]}"; do
  IFS='|' read -r cert_id domain days status <<<"$row"
  expiry="$(_date_in_days "$days")"

  # ExpiryDate is OwnerIndex's RANGE key. Omitting it does not error — DynamoDB
  # just leaves the item out of the index, so GET /certs would never return it.
  aws dynamodb put-item --table-name "$CERT_TABLE" --region "$REGION" --item "$(cat <<EOF
{
  "CertId":     {"S": "$cert_id"},
  "OwnerId":    {"S": "$USER_SUB"},
  "CertType":   {"S": "ACM"},
  "Domain":     {"S": "$domain"},
  "ExpiryDate": {"S": "$expiry"},
  "Status":     {"S": "$status"},
  "Source":     {"S": "seed.sh"},
  "Version":    {"N": "$(date +%s)"}
}
EOF
)"
  pass "$cert_id  ($domain, expires $expiry, ${days}d)"
done

# --- Seed IAM accounts ---------------------------------------------------------
step "Seeding IAM accounts into $IAM_TABLE"
for row in "${SEED_IAM_ACCOUNTS[@]}"; do
  IFS='|' read -r account_hash days status <<<"$row"
  next_rotation="$(_date_in_days "$days")"

  # NextRotationDate is OwnerIndex's RANGE key — same trap as ExpiryDate above.
  aws dynamodb put-item --table-name "$IAM_TABLE" --region "$REGION" --item "$(cat <<EOF
{
  "AccountIdHash":    {"S": "$account_hash"},
  "OwnerId":          {"S": "$USER_SUB"},
  "NextRotationDate": {"S": "$next_rotation"},
  "Status":           {"S": "$status"},
  "Source":           {"S": "seed.sh"}
}
EOF
)"
  pass "$account_hash  (next rotation $next_rotation, $status)"
done

# --- Seed audit events --------------------------------------------------------
# The Audit tab searches by entity id, and a non-admin may only query their own
# sub — so seed against the sub, or the tab has nothing to show.
step "Seeding audit events into $AUDIT_TABLE"
AUDIT_EVENTS=(
  "DISCOVERY_COMPLETED|SUCCESS|discovered 5 certificates, 3 IAM accounts"
  "EXPIRY_EVALUATED|SUCCESS|1 certificate within 7 days, 2 within 30"
  "NOTIFICATION_SENT|SUCCESS|high-severity alert published to SNS"
)
now_epoch="$(date +%s)"
i=0
for row in "${AUDIT_EVENTS[@]}"; do
  IFS='|' read -r event_type outcome detail <<<"$row"
  # ISO-8601, matching what crm_common.put_audit_event and the Step Functions
  # native putItem integration ($$.State.EnteredTime) both write.
  ts="$(python3 -c "
import datetime, sys
print(datetime.datetime.fromtimestamp(int(sys.argv[1]) - int(sys.argv[2]) * 3600, datetime.timezone.utc).isoformat())
" "$now_epoch" "$((i + 1))")"

  aws dynamodb put-item --table-name "$AUDIT_TABLE" --region "$REGION" --item "$(cat <<EOF
{
  "EntityId":       {"S": "$USER_SUB"},
  "EventTimestamp": {"S": "$ts"},
  "EventType":      {"S": "$event_type"},
  "Actor":          {"S": "seed.sh"},
  "Outcome":        {"S": "$outcome"},
  "Detail":         {"M": {"note": {"S": "$detail"}}},
  "ExpiresAt":      {"N": "$((now_epoch + 90 * 86400))"}
}
EOF
)"
  pass "$event_type at $ts"
  i=$((i + 1))
done

cat <<EOF

$(printf '\033[32mSeeded %s certificates, %s IAM accounts, %s audit events.\033[0m' \
  "${#SEED_CERTS[@]}" "${#SEED_IAM_ACCOUNTS[@]}" "${#AUDIT_EVENTS[@]}")

Open $APP_URL and sign in as $TARGET_EMAIL:

  Certificates   5 rows, colour-coded red / amber / green by days remaining.
                 "Renew" starts the renewal state machine and writes an audit
                 event, so it also exercises the write path.
  IAM Accounts   3 rows. "Rotate" starts the rotation state machine.
  Audit          search for  $USER_SUB  to see the seeded events, plus anything
                 your own Renew/Rotate clicks appended.

Remove it all again with:
  ./scripts/seed.sh $TARGET_EMAIL --clean
EOF
