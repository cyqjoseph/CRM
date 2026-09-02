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

# --- Confirm the EC2 certificate discovery path works once, right after deploy ---
# Same reasoning as above: don't wait for Ec2DiscoveryScheduleRule's first
# 30-minute tick to find out the SSM dispatch is broken.
#
# Retried, unlike the two above, because this one races the instance's own boot.
# A new or replaced instance has to finish cloud-init (apt, then generating its
# internal CA and signing a certificate per host) and register with SSM before a
# scan can return anything, which takes a couple of minutes — and a single early
# invocation reports zero certificates found, which is indistinguishable from a
# broken scan. Give it a few minutes, and stop as soon as application
# certificates come back.
#
# A failure here must never fail the deploy — the 30-minute schedule retries.
EC2_DISCOVERY_ATTEMPTS="${EC2_DISCOVERY_ATTEMPTS:-10}"
EC2_DISCOVERY_INTERVAL="${EC2_DISCOVERY_INTERVAL:-30}"
for ATTEMPT in $(seq 1 "$EC2_DISCOVERY_ATTEMPTS"); do
  if aws lambda invoke --function-name app-d9fae51c-1929cc69-ec2-discovery-fn \
       --region "$REGION" --cli-binary-format raw-in-base64-out --payload '{}' \
       /tmp/ec2-discovery-invoke.json >/dev/null; then
    APP_CERTS="$(jq -r '.appCerts // 0' /tmp/ec2-discovery-invoke.json 2>/dev/null || echo 0)"
    if [ "$APP_CERTS" != "0" ] && [ "$APP_CERTS" != "null" ]; then
      echo "ec2-discovery-fn found $APP_CERTS application certificate(s) on attempt $ATTEMPT"
      break
    fi
    echo "ec2-discovery-fn returned no application certificates (attempt $ATTEMPT/$EC2_DISCOVERY_ATTEMPTS) — the instance is probably still issuing them"
  else
    echo "warning: ec2-discovery-fn invocation failed (attempt $ATTEMPT/$EC2_DISCOVERY_ATTEMPTS)" >&2
  fi
  [ "$ATTEMPT" -lt "$EC2_DISCOVERY_ATTEMPTS" ] && sleep "$EC2_DISCOVERY_INTERVAL"
done
if [ "${APP_CERTS:-0}" = "0" ]; then
  echo "warning: no application certificates discovered from the cert-scanner instance yet — it will retry on the next 30-minute schedule" >&2
fi

# --- Seed demo inventory rows the UI can render and act on ---------------------
# ONE seed, into the SHARED TEAM PARTITION (crm-resource-owners). OwnerId is
# OwnerIndex's HASH key and GET /certs reads that partition for every
# authenticated caller, so one seed serves the whole team.
#
# This used to seed each known Cognito sub separately, with different volumes per
# sub — which is exactly why members signed into the same CRM saw different
# certificates, or none at all. Genuinely discovered rows had the same problem
# from the other direction: discovery derives OwnerId from an IAM path, a resource
# tag or the scanner's own identity, never from a Cognito sub, so they belonged to
# no login either. Both now write the shared partition.
#
# Override the volume without editing this file:
#   SEED_CERTS=200 ./deploy.sh
# SEED_OWNER_ID still targets a single sub instead, but only do that to reproduce
# the per-login isolation described above.
#
# Seeding must never abort an otherwise-successful deploy — every id starts with
# `demo-` and every write is an idempotent upsert, so a retry is always safe.
SEED_CERTS="${SEED_CERTS:-40}"
SEED_ACCOUNTS="${SEED_ACCOUNTS:-15}"
SEED_AUDIT_EVENTS="${SEED_AUDIT_EVENTS:-30}"
SEED_OWNER_ID="${SEED_OWNER_ID:-crm-resource-owners}"

# Retire rows left owned by an individual login. Demo ids are deterministic and a
# --clean pass is keyed on the id alone, so cleaning these subs and then seeding
# the shared partition below leaves exactly one copy of each row, owned by the
# whole team. Without it every member keeps seeing their own private leftovers on
# top of the shared inventory — the same inconsistency in a quieter form.
# Generous counts, because the two subs were seeded with different volumes (40
# and 3), and removing a key that does not exist is a no-op.
LEGACY_SEEDED_SUBS=(
  "d9ca551c-d0a1-7011-1c4f-99a48c8d917f"
  "c90a255c-3071-708a-2806-987b385b1376"
)
if [ "${SEED_DEMO_DATA:-true}" = "true" ]; then
  for LEGACY_SUB in "${LEGACY_SEEDED_SUBS[@]}"; do
    REGION="$REGION" ./scripts/seed-demo-data.sh --clean \
      --owner-id "$LEGACY_SUB" \
      --certs 250 --accounts 60 --audit-events 120 \
      || echo "warning: could not retire per-login demo rows for $LEGACY_SUB" >&2
  done
fi

if [ "${SEED_DEMO_DATA:-true}" = "true" ]; then
  REGION="$REGION" SEED_OWNER_ID="$SEED_OWNER_ID" ./scripts/seed-demo-data.sh \
    --certs "$SEED_CERTS" \
    --accounts "$SEED_ACCOUNTS" \
    --audit-events "$SEED_AUDIT_EVENTS" \
    || echo "warning: demo data seeding failed — the UI may show no rows until it is re-run" >&2
fi

# --- Retire the five fixed rows an earlier deploy.sh left behind ----------------
# A previous version of this script wrote cert-001/002/003 and hash-acct-001/002
# with hand-written put-item calls, owned by one Cognito sub, carrying hardcoded
# 2025 dates and a status vocabulary ("active"/"warning"/"critical") that no query
# in this application uses. That script is gone (commit 6e12d0d) but its rows are
# not: nothing owns them, nothing updates them, and they appear in one member's
# dashboard and nobody else's.
#
# Named individually rather than matched by prefix, so this can never reach a
# discovered or seeded row. Handled by the same generator as everything else, so
# there are no ad-hoc delete calls in this script.
if [ "${SEED_DEMO_DATA:-true}" = "true" ]; then
  REGION="$REGION" ./scripts/seed-demo-data.sh --retire-legacy-fixed-rows \
    || echo "warning: could not retire the legacy fixed demo rows" >&2
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
