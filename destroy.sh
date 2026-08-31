#!/usr/bin/env bash
# Tears down everything deploy.sh created. Idempotent; safe to re-run.
# Exits non-zero on failure.
set -euo pipefail

REGION="ap-southeast-1"
STACK_NAME="app-d9fae51c-1929cc69-crm"
ECR_REPO="app-d9fae51c-1929cc69-ad-agent"
UI_BUCKET="app-d9fae51c-1929cc69-ui-site"
ARCHIVE_BUCKET="app-d9fae51c-1929cc69-audit-archive"
OUTPUTS_FILE="outputs.json"

# --- Empty S3 buckets the stack owns; DeleteStack fails on non-empty buckets ---
for BUCKET in "$UI_BUCKET" "$ARCHIVE_BUCKET"; do
  if aws s3api head-bucket --bucket "$BUCKET" --region "$REGION" 2>/dev/null; then
    aws s3 rm "s3://${BUCKET}" --region "$REGION" --recursive
  fi
done

# --- Delete the CloudFormation stack (owns everything except the ECR repo) ---
aws cloudformation delete-stack --stack-name "$STACK_NAME" --region "$REGION"
aws cloudformation wait stack-delete-complete --stack-name "$STACK_NAME" --region "$REGION"

# --- Delete the ECR repository directly; CloudFormation never owned it ---
aws ecr delete-repository --repository-name "$ECR_REPO" --region "$REGION" --force 2>/dev/null || true

rm -f "$OUTPUTS_FILE"

echo "destroy complete"
