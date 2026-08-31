#!/usr/bin/env bash
# Resolves the stack's CloudFormation outputs into shell variables.
#
# Sourced by scripts/validate.sh and scripts/seed.sh. Not meant to be run.
#
# Prefers the repo-root outputs.json that ./deploy.sh writes, but falls back to
# querying CloudFormation directly. The fallback is the normal path here, not an
# edge case: this project redeploys on push to main, so ./deploy.sh runs on the
# platform's build host and never on your machine — and outputs.json is in
# .gitignore, so it is not in a fresh clone either. A script that insisted on the
# file would fail on every developer's first run with "run ./deploy.sh first",
# which is advice you cannot act on locally.
#
# Exports: API_URL APP_URL USER_POOL_ID USER_POOL_CLIENT_ID

set -euo pipefail

: "${REGION:=ap-southeast-1}"
: "${STACK_NAME:=app-d9fae51c-1929cc69-crm}"

OUTPUTS_JSON=""

if [ -f "outputs.json" ]; then
  OUTPUTS_SOURCE="outputs.json"
  # deploy.sh writes a flat {"Key": "Value"} object.
  OUTPUTS_JSON="$(cat outputs.json)"
else
  OUTPUTS_SOURCE="CloudFormation stack $STACK_NAME"
  RAW="$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" --region "$REGION" \
    --query "Stacks[0].Outputs" --output json 2>/dev/null || echo "")"

  if [ -z "$RAW" ] || [ "$RAW" = "null" ]; then
    echo "error: no outputs.json and could not read stack $STACK_NAME in $REGION." >&2
    echo "       Check your AWS credentials and that the stack is deployed." >&2
    exit 1
  fi

  # Flatten to the same shape as outputs.json so both paths read identically.
  OUTPUTS_JSON="$(printf '%s' "$RAW" \
    | jq 'reduce .[] as $o ({}; .[$o.OutputKey] = $o.OutputValue)')"
fi

_output() {
  printf '%s' "$OUTPUTS_JSON" | jq -r --arg k "$1" '.[$k] // empty'
}

API_URL="$(_output ApiUrl)"
APP_URL="$(_output AppUrl)"
[ -n "$APP_URL" ] || APP_URL="$(_output app_url)"
USER_POOL_ID="$(_output UserPoolId)"
USER_POOL_CLIENT_ID="$(_output UserPoolClientId)"

for pair in \
  "ApiUrl:$API_URL" \
  "UserPoolId:$USER_POOL_ID" \
  "UserPoolClientId:$USER_POOL_CLIENT_ID"
do
  if [ -z "${pair#*:}" ]; then
    echo "error: ${pair%%:*} missing from $OUTPUTS_SOURCE" >&2
    exit 1
  fi
done

# Trailing slash on ApiUrl would produce a double slash in every request path.
API_URL="${API_URL%/}"
APP_URL="${APP_URL%/}"

export API_URL APP_URL USER_POOL_ID USER_POOL_CLIENT_ID OUTPUTS_SOURCE

# Running this file directly is the obvious way to check "are my credentials and
# stack reachable?" — but as a pure library it answered that question with total
# silence and exit 0, which is indistinguishable from doing nothing. Print what
# was resolved when executed, stay quiet when sourced.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  printf 'resolved from %s\n\n' "$OUTPUTS_SOURCE"
  printf '  API_URL              %s\n' "$API_URL"
  printf '  APP_URL              %s\n' "$APP_URL"
  printf '  USER_POOL_ID         %s\n' "$USER_POOL_ID"
  printf '  USER_POOL_CLIENT_ID  %s\n' "$USER_POOL_CLIENT_ID"
  printf '\nThis file is a library — source it, or run:\n'
  printf '  ./scripts/validate.sh\n'
  printf '  ./scripts/seed.sh <email>\n'
fi
