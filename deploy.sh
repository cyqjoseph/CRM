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

# --- Confirm the EC2 OS-certificate discovery path works once, right after deploy ---
# Same reasoning as above: don't wait for Ec2DiscoveryScheduleRule's first
# 30-minute tick to find out the SSM dispatch is broken. A failure here must
# never fail the deploy — the schedule retries on its own.
aws lambda invoke --function-name app-d9fae51c-1929cc69-ec2-discovery-fn \
  --region "$REGION" --cli-binary-format raw-in-base64-out --payload '{}' \
  /tmp/ec2-discovery-invoke.json \
  || echo "warning: ec2-discovery-fn invocation failed — it will retry on the next 30-minute schedule" >&2

# --- Seed demo inventory rows the UI can render and act on ---------------------
# Discovery and the API disagree about what OwnerId means: discovery derives it
# from an IAM path or a resource tag, while GET /certs and GET /iam/accounts
# query OwnerIndex with the caller's Cognito `sub`. So genuinely discovered rows
# belong to no human login and appear in nobody's UI. These rows are written
# against a known sub so the dashboard has data and every control (Renew, Rotate,
# Details, Request Password Reset) can be exercised end to end.
#
# Override the target login and the volume without editing this file:
#   SEED_OWNER_ID=<your-cognito-sub> SEED_CERTS=200 ./deploy.sh
#
# Seeding must never abort an otherwise-successful deploy — every id starts with
# `demo-` and every write is an idempotent upsert, so a retry is always safe.
SEED_CERTS="${SEED_CERTS:-40}"
SEED_ACCOUNTS="${SEED_ACCOUNTS:-15}"
SEED_AUDIT_EVENTS="${SEED_AUDIT_EVENTS:-30}"

if [ "${SEED_DEMO_DATA:-true}" = "true" ]; then
  REGION="$REGION" SEED_OWNER_ID="${SEED_OWNER_ID:-}" ./scripts/seed-demo-data.sh \
    --certs "$SEED_CERTS" \
    --accounts "$SEED_ACCOUNTS" \
    --audit-events "$SEED_AUDIT_EVENTS" \
    || echo "warning: demo data seeding failed — the UI may show no rows until it is re-run" >&2
fi

# --- Seed a second known login (sihaochow@gmail.com, sub c90a255c-3071-708a-2806-987b385b1376) ---
# Same mechanism as above, against a second Cognito sub, so that login also has
# rows without anyone needing to override SEED_OWNER_ID. Just 3 certs, one per
# expiry colour band (red/amber/green), which is all a smoke test needs.
SEED_EXTRA_OWNER_ID="${SEED_EXTRA_OWNER_ID:-c90a255c-3071-708a-2806-987b385b1376}"
SEED_EXTRA_CERTS="${SEED_EXTRA_CERTS:-3}"

if [ "${SEED_DEMO_DATA:-true}" = "true" ] && [ -n "$SEED_EXTRA_OWNER_ID" ]; then
  REGION="$REGION" ./scripts/seed-demo-data.sh \
    --owner-id "$SEED_EXTRA_OWNER_ID" \
    --certs "$SEED_EXTRA_CERTS" \
    --accounts 0 \
    --audit-events 0 \
    || echo "warning: demo data seeding failed for $SEED_EXTRA_OWNER_ID" >&2
fi

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
