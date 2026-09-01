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
  "app-d9fae51c-1929cc69-test-instance-registry"
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

# --- Seed real inventory by invoking the discovery Lambdas once after deploy ---
# discovery-iam-fn scans real IAM users/access keys — an allowed service with no
# permissions-boundary restriction — so invoking it here guarantees iam-accounts
# has data without waiting for the daily EventBridge schedule (DiscoveryScheduleRule).
# discovery-acm-fn is invoked too: its ACM sub-scan is denied by the account's
# permissions boundary (ACM is not in CLAUDE.md's allowed-services list), but each
# discovery source degrades independently, so it still writes any Secrets-Manager-
# tagged or IAM server certificates it finds on top of the simulated rows seeded
# below. Neither invocation failing should fail the deploy — the schedule will
# retry it on its own cadence.
aws lambda invoke --function-name app-d9fae51c-1929cc69-discovery-iam-fn \
  --region "$REGION" --cli-binary-format raw-in-base64-out --payload '{}' \
  /tmp/discovery-iam-invoke.json \
  || echo "warning: discovery-iam-fn invocation failed — iam-accounts may be empty until the next scheduled run" >&2
aws lambda invoke --function-name app-d9fae51c-1929cc69-discovery-acm-fn \
  --region "$REGION" --cli-binary-format raw-in-base64-out --payload '{}' \
  /tmp/discovery-acm-invoke.json \
  || echo "warning: discovery-acm-fn invocation failed — non-ACM cert sources may be empty until the next scheduled run" >&2

# --- Seed simulated ACM certificates correlated to the 3 EC2 test instances ---
# A real ACM certificate cannot be issued for an invented hostname like
# "crm-test-1.internal.example.com" — public issuance requires DNS/email
# domain-ownership validation, which this project has no real zone for. These
# rows simulate that inventory directly, correlated by instance id, so the UI's
# certificate dashboard has real EC2-backed data to show end to end.
CERT_TABLE="$(jq -r '.[] | select(.OutputKey=="CertInventoryTableName") | .OutputValue' /tmp/"${STACK_NAME}"-outputs.json)"
for i in 1 2 3; do
  INSTANCE_ID="$(jq -r ".[] | select(.OutputKey==\"TestInstance${i}Id\") | .OutputValue" /tmp/"${STACK_NAME}"-outputs.json)"
  DOMAIN="crm-test-${i}.internal.example.com"
  NOW_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  EXPIRY_ISO="$(date -u -d "+90 days" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+90d +%Y-%m-%dT%H:%M:%SZ)"

  aws dynamodb put-item \
    --table-name "$CERT_TABLE" --region "$REGION" \
    --item "{
      \"CertId\": {\"S\": \"sim-cert-crm-test-${i}\"},
      \"CertType\": {\"S\": \"SIMULATED_ACM\"},
      \"OwnerId\": {\"S\": \"${DOMAIN}\"},
      \"Domain\": {\"S\": \"${DOMAIN}\"},
      \"ExpiryDate\": {\"S\": \"${EXPIRY_ISO}\"},
      \"Status\": {\"S\": \"ISSUED\"},
      \"Source\": {\"S\": \"AWS_ACM\"},
      \"EnvironmentTag\": {\"S\": \"aws\"},
      \"LastSyncedAt\": {\"S\": \"${NOW_ISO}\"},
      \"InstanceId\": {\"S\": \"${INSTANCE_ID}\"},
      \"Version\": {\"N\": \"1\"}
    }"
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
