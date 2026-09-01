#!/usr/bin/env bash
# Builds and deploys the Centralised Resource Manager SAM application.
# Idempotent; safe to re-run. Exits non-zero on failure.
set -euo pipefail

REGION="ap-southeast-1"
STACK_NAME="app-d9fae51c-1929cc69-crm"
ARTIFACTS_BUCKET="app-d9fae51c-1929cc69-artifacts"
TEMPLATE_FILE="template.yaml"
OUTPUTS_FILE="outputs.json"

# Every AWS::SecretsManager::Secret name in template.yaml. Kept in sync by
# tests/test_scripts.py::test_both_scripts_cover_every_secret_in_the_template.
SECRET_NAMES=(
  "app-d9fae51c-1929cc69-jira-token"
  "app-d9fae51c-1929cc69-password-reset-credentials"
)

if [ ! -f "$TEMPLATE_FILE" ]; then
  echo "error: $TEMPLATE_FILE not found at repo root — nothing to deploy" >&2
  exit 1
fi

# --- Report the ROOT cause when a deploy fails ---------------------------------
# A rollback stamps "Resource creation cancelled" on every resource that was
# merely queued behind the one that actually failed. `sam deploy` surfaces that
# cascade and not the reason, so a failed deploy looks unattributable. Print the
# real failures — those with a reason other than the cancellation boilerplate.
dump_stack_failures() {
  echo "" >&2
  echo "=== root CloudFormation failures for $STACK_NAME (oldest first) ===" >&2
  aws cloudformation describe-stack-events \
      --stack-name "$STACK_NAME" --region "$REGION" \
      --query "reverse(StackEvents[?contains(ResourceStatus, 'FAILED') && ResourceStatusReason != 'Resource creation cancelled'].[Timestamp, LogicalResourceId, ResourceType, ResourceStatusReason])" \
      --output table >&2 \
    || echo "(could not read stack events for $STACK_NAME)" >&2
  echo "=== end of root failures ===" >&2
}

# --- Preflight: purge secrets left "scheduled for deletion" -------------------
# CloudFormation's DeleteStack does NOT purge a Secrets Manager secret; it only
# schedules deletion behind a recovery window (30 days by default), and the name
# stays reserved for that whole window. Re-creating the same name then fails at
# once with "already scheduled for deletion". JiraTokenSecret is dependency-free,
# so it sits in CloudFormation's FIRST creation wave alongside the DynamoDB
# tables, S3 buckets, SNS topics and SQS queues — one failing there cancels all
# of them, which is why such a rollback shows nothing but cancellations.
# restore-secret first: delete-secret --force-delete-without-recovery is
# rejected on a secret that is already scheduled for deletion.
for SECRET in "${SECRET_NAMES[@]}"; do
  DELETED_DATE="$(aws secretsmanager describe-secret \
    --secret-id "$SECRET" --region "$REGION" \
    --query 'DeletedDate' --output text 2>/dev/null || echo ABSENT)"

  if [ "$DELETED_DATE" != "ABSENT" ] && [ "$DELETED_DATE" != "None" ]; then
    echo "preflight: $SECRET is scheduled for deletion ($DELETED_DATE) — purging so it can be re-created"
    aws secretsmanager restore-secret --secret-id "$SECRET" --region "$REGION" >/dev/null
    aws secretsmanager delete-secret --secret-id "$SECRET" --region "$REGION" \
      --force-delete-without-recovery >/dev/null

    # The name is not reusable until the purge lands; poll rather than guess.
    for _ in $(seq 1 30); do
      aws secretsmanager describe-secret --secret-id "$SECRET" --region "$REGION" \
        >/dev/null 2>&1 || break
      sleep 2
    done
  fi
done

# --- Artifacts bucket for `sam deploy` (never use --resolve-s3/--guided; see CLAUDE.md) ---
if ! aws s3api head-bucket --bucket "$ARTIFACTS_BUCKET" --region "$REGION" 2>/dev/null; then
  if [ "$REGION" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$ARTIFACTS_BUCKET" --region "$REGION"
  else
    aws s3api create-bucket --bucket "$ARTIFACTS_BUCKET" --region "$REGION" \
      --create-bucket-configuration LocationConstraint="$REGION"
  fi
fi

# --- Build and deploy the SAM stack ---
sam build --template-file "$TEMPLATE_FILE"

DEPLOY_ARGS=(
  --stack-name "$STACK_NAME"
  --s3-bucket "$ARTIFACTS_BUCKET"
  --region "$REGION"
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM
  --no-fail-on-empty-changeset
  --no-confirm-changeset
)

sam deploy "${DEPLOY_ARGS[@]}" || { dump_stack_failures; exit 1; }

# --- Fetch the stack's CloudFormation outputs (reused below) ---
aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" \
  --query "Stacks[0].Outputs" --output json > /tmp/"${STACK_NAME}"-outputs.json

# --- Populate real inventory by invoking the discovery Lambdas once after deploy ---
# Both scan services the boundary permits (IAM users/access keys, IAM server
# certificates, tagged Secrets Manager entries), so this gives the tables real
# data immediately instead of waiting for the daily DiscoveryScheduleRule.
# Neither invocation failing should fail the deploy — the schedule retries.
aws lambda invoke --function-name app-d9fae51c-1929cc69-discovery-iam-fn \
  --region "$REGION" --cli-binary-format raw-in-base64-out --payload '{}' \
  /tmp/discovery-iam-invoke.json \
  || echo "warning: discovery-iam-fn invocation failed — iam-accounts may be empty until the next scheduled run" >&2
aws lambda invoke --function-name app-d9fae51c-1929cc69-discovery-acm-fn \
  --region "$REGION" --cli-binary-format raw-in-base64-out --payload '{}' \
  /tmp/discovery-acm-invoke.json \
  || echo "warning: discovery-acm-fn invocation failed — cert-inventory may be empty until the next scheduled run" >&2

# --- Seed demo inventory rows the UI can render and act on ---------------------
# Discovery and the API disagree about what OwnerId means: discovery derives it
# from an IAM path or a resource tag, while GET /certs and GET /iam/accounts
# query OwnerIndex with the caller's Cognito `sub`. So genuinely discovered rows
# belong to no human login and appear in nobody's UI. These rows are written
# against a known sub so the dashboard has something to show and every control
# (Renew, Rotate, Details, Request Password Reset) can be exercised end to end.
#
# Override with SEED_OWNER_ID=<your-cognito-sub> ./deploy.sh to target a
# different login; find yours in the Cognito console, or in any api-certs-fn log
# line's `ownerId` field after signing in once.
#
# Field names matter and are easy to get wrong:
#   - ExpiryDate / NextRotationDate are OwnerIndex's RANGE key on their table.
#     DynamoDB accepts a row without one and then silently omits it from the
#     index, so GET /certs would never return it.
#   - The UI renders `Status` (not `RotationStatus`) and `UserName` on the IAM
#     tab, and rotation.asl.json writes back to `Status`.
# Dates are computed relative to now, not hardcoded — a fixed date silently ages
# into the past and makes every row render as long expired.
SEED_OWNER_ID="${SEED_OWNER_ID:-d9ca551c-d0a1-7011-1c4f-99a48c8d917f}"

CERT_TABLE="$(jq -r '.[] | select(.OutputKey=="CertInventoryTableName") | .OutputValue' /tmp/"${STACK_NAME}"-outputs.json)"
IAM_TABLE="$(jq -r '.[] | select(.OutputKey=="IamAccountsTableName") | .OutputValue' /tmp/"${STACK_NAME}"-outputs.json)"

_in_days() {
  date -u -d "+$1 days" +%Y-%m-%d 2>/dev/null || date -u -v"+$1"d +%Y-%m-%d
}

# `put-item` is an unconditional upsert, so re-running deploy.sh is idempotent.
# A seed failure must never abort an otherwise-successful deploy.
seed_item() {
  local table="$1" item="$2" label="$3"
  if aws dynamodb put-item --table-name "$table" --region "$REGION" --item "$item"; then
    echo "seed: wrote $label to $table"
  else
    echo "warning: failed to seed $label into $table — the UI may show no data for it until the next deploy" >&2
  fi
}

# Expiry offsets deliberately span all three bands the UI colours:
#   <= 7 days -> red    <= 30 days -> amber    else green
# id|domain|days-to-expiry|type
for row in \
  "cert-001|payments.internal.example.com|3|ACM" \
  "cert-002|sso.internal.example.com|21|Self-Signed" \
  "cert-003|api.internal.example.com|75|On-Prem"
do
  IFS='|' read -r cert_id domain days cert_type <<<"$row"
  seed_item "$CERT_TABLE" "$(cat <<EOF
{
  "CertId":      {"S": "${cert_id}"},
  "CertType":    {"S": "${cert_type}"},
  "OwnerId":     {"S": "${SEED_OWNER_ID}"},
  "Domain":      {"S": "${domain}"},
  "ExpiryDate":  {"S": "$(_in_days "$days")"},
  "Status":      {"S": "ISSUED"},
  "Source":      {"S": "seed"},
  "Version":     {"N": "$(date +%s)"}
}
EOF
)" "$cert_id"
done

# id|username|days-to-next-rotation|status
for row in \
  "hash-acct-001|svc-payments|4|warning" \
  "hash-acct-002|svc-reporting|45|active"
do
  IFS='|' read -r account_hash user_name days status <<<"$row"
  seed_item "$IAM_TABLE" "$(cat <<EOF
{
  "AccountIdHash":    {"S": "${account_hash}"},
  "UserName":         {"S": "${user_name}"},
  "OwnerId":          {"S": "${SEED_OWNER_ID}"},
  "NextRotationDate": {"S": "$(_in_days "$days")"},
  "Status":           {"S": "${status}"},
  "Source":           {"S": "seed"}
}
EOF
)" "$account_hash"
done

# --- Sync the static self-service UI to S3 and invalidate the CloudFront cache ---
if [ -d "ui" ]; then
  UI_BUCKET="$(jq -r '.[] | select(.OutputKey=="UiSiteBucketName") | .OutputValue' /tmp/"${STACK_NAME}"-outputs.json)"
  DISTRIBUTION_ID="$(jq -r '.[] | select(.OutputKey=="CloudFrontDistributionId") | .OutputValue' /tmp/"${STACK_NAME}"-outputs.json)"
  API_URL="$(jq -r '.[] | select(.OutputKey=="ApiUrl") | .OutputValue' /tmp/"${STACK_NAME}"-outputs.json)"
  USER_POOL_ID="$(jq -r '.[] | select(.OutputKey=="UserPoolId") | .OutputValue' /tmp/"${STACK_NAME}"-outputs.json)"
  USER_POOL_CLIENT_ID="$(jq -r '.[] | select(.OutputKey=="UserPoolClientId") | .OutputValue' /tmp/"${STACK_NAME}"-outputs.json)"

  aws s3 sync ui/ "s3://${UI_BUCKET}/" --region "$REGION" --delete

  cat > /tmp/config.js <<EOF
window.CRM_CONFIG = {
  region: "${REGION}",
  userPoolId: "${USER_POOL_ID}",
  userPoolClientId: "${USER_POOL_CLIENT_ID}",
  apiUrl: "${API_URL}",
};
EOF
  aws s3 cp /tmp/config.js "s3://${UI_BUCKET}/config.js" --region "$REGION"

  aws cloudfront create-invalidation --distribution-id "$DISTRIBUTION_ID" --paths "/*" >/dev/null
fi

# --- Write outputs.json from the stack's CloudFormation outputs ---
jq 'reduce (. // [])[] as $o ({}; .[$o.OutputKey] = $o.OutputValue)
    | if has("AppUrl") then . + {app_url: .AppUrl} else . end' \
  /tmp/"${STACK_NAME}"-outputs.json > "$OUTPUTS_FILE"

echo "deploy complete — outputs written to $OUTPUTS_FILE"
