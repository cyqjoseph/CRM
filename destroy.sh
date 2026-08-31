#!/usr/bin/env bash
# Tears down everything deploy.sh created. Idempotent; safe to re-run.
# Exits non-zero on failure.
set -euo pipefail

REGION="ap-southeast-1"
STACK_NAME="app-d9fae51c-1929cc69-crm"
UI_BUCKET="app-d9fae51c-1929cc69-ui-site"
ARCHIVE_BUCKET="app-d9fae51c-1929cc69-audit-archive"
OUTPUTS_FILE="outputs.json"

# Every AWS::SecretsManager::Secret name in template.yaml. Kept in sync by
# tests/test_scripts.py::test_both_scripts_cover_every_secret_in_the_template.
SECRET_NAMES=(
  "app-d9fae51c-1929cc69-test-instance-registry"
  "app-d9fae51c-1929cc69-jira-token"
  "app-d9fae51c-1929cc69-password-reset-credentials"
)

# --- Empty S3 buckets the stack owns; DeleteStack fails on non-empty buckets ---
for BUCKET in "$UI_BUCKET" "$ARCHIVE_BUCKET"; do
  if aws s3api head-bucket --bucket "$BUCKET" --region "$REGION" 2>/dev/null; then
    aws s3 rm "s3://${BUCKET}" --region "$REGION" --recursive
  fi
done

# --- Delete the CloudFormation stack (owns everything except the ECR repo) ---
aws cloudformation delete-stack --stack-name "$STACK_NAME" --region "$REGION"
aws cloudformation wait stack-delete-complete --stack-name "$STACK_NAME" --region "$REGION"

# --- Purge the secrets outright -----------------------------------------------
# DeleteStack above only *scheduled* these for deletion, behind a 30-day recovery
# window that keeps the names reserved. Leaving them in that state makes the next
# ./deploy.sh fail at CREATE with "already scheduled for deletion", which — since
# JiraTokenSecret is in CloudFormation's first creation wave — cancels every
# table, bucket, topic and queue beside it. Must run AFTER DeleteStack, or the
# stack deletion simply re-schedules them.
for SECRET in "${SECRET_NAMES[@]}"; do
  if aws secretsmanager describe-secret --secret-id "$SECRET" --region "$REGION" >/dev/null 2>&1; then
    # A secret already scheduled for deletion rejects --force-delete-without-recovery.
    aws secretsmanager restore-secret --secret-id "$SECRET" --region "$REGION" >/dev/null 2>&1 || true
    aws secretsmanager delete-secret --secret-id "$SECRET" --region "$REGION" \
      --force-delete-without-recovery >/dev/null 2>&1 || true
  fi
done

rm -f "$OUTPUTS_FILE"

echo "destroy complete"
