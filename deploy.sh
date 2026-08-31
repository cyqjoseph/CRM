#!/usr/bin/env bash
# Builds and deploys the Centralised Resource Manager SAM application.
# Idempotent; safe to re-run. Exits non-zero on failure.
set -euo pipefail

REGION="ap-southeast-1"
STACK_NAME="app-d9fae51c-1929cc69-crm"
ARTIFACTS_BUCKET="app-d9fae51c-1929cc69-artifacts"
TEMPLATE_FILE="template.yaml"
ECR_REPO="app-d9fae51c-1929cc69-ad-agent"
AD_AGENT_DIR="ad-agent"
OUTPUTS_FILE="outputs.json"

if [ ! -f "$TEMPLATE_FILE" ]; then
  echo "error: $TEMPLATE_FILE not found at repo root — nothing to deploy" >&2
  exit 1
fi

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"

# --- Artifacts bucket for `sam deploy` (never use --resolve-s3/--guided; see CLAUDE.md) ---
if ! aws s3api head-bucket --bucket "$ARTIFACTS_BUCKET" --region "$REGION" 2>/dev/null; then
  if [ "$REGION" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$ARTIFACTS_BUCKET" --region "$REGION"
  else
    aws s3api create-bucket --bucket "$ARTIFACTS_BUCKET" --region "$REGION" \
      --create-bucket-configuration LocationConstraint="$REGION"
  fi
fi

DEPLOY_PARAM_OVERRIDES=()

# --- AD discovery/rotation Fargate agent image (ECR repo is NOT owned by the stack) ---
if [ -d "$AD_AGENT_DIR" ]; then
  ECR_URI="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO}"

  aws ecr describe-repositories --repository-names "$ECR_REPO" --region "$REGION" >/dev/null 2>&1 \
    || aws ecr create-repository --repository-name "$ECR_REPO" --region "$REGION" >/dev/null

  aws ecr get-login-password --region "$REGION" \
    | docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

  docker build -t "${ECR_URI}:latest" "$AD_AGENT_DIR"
  docker push "${ECR_URI}:latest"

  DEPLOY_PARAM_OVERRIDES+=("AdAgentImageUri=${ECR_URI}:latest")
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

if [ "${#DEPLOY_PARAM_OVERRIDES[@]}" -gt 0 ]; then
  DEPLOY_ARGS+=(--parameter-overrides "${DEPLOY_PARAM_OVERRIDES[@]}")
fi

sam deploy "${DEPLOY_ARGS[@]}"

# --- Write outputs.json from the stack's CloudFormation outputs ---
aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" \
  --query "Stacks[0].Outputs" --output json > /tmp/"${STACK_NAME}"-outputs.json

jq 'reduce (. // [])[] as $o ({}; .[$o.OutputKey] = $o.OutputValue)
    | if has("AppUrl") then . + {app_url: .AppUrl} else . end' \
  /tmp/"${STACK_NAME}"-outputs.json > "$OUTPUTS_FILE"

echo "deploy complete — outputs written to $OUTPUTS_FILE"
