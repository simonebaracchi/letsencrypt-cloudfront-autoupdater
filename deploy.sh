#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ── parse CLI arguments ──────────────────────────────────────────────────────
CLI_PROFILE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            CLI_PROFILE="$2"
            shift 2
            ;;
        --profile=*)
            CLI_PROFILE="${1#--profile=}"
            shift
            ;;
        *)
            echo "Usage: $0 [--profile AWS_PROFILE]"
            exit 1
            ;;
    esac
done

# ── prerequisites ────────────────────────────────────────────────────────────
for cmd in aws python3; do
    command -v "$cmd" >/dev/null || { echo "Error: $cmd not found."; exit 1; }
done

python3 -m pip --version >/dev/null 2>&1 || { echo "Error: pip not found."; exit 1; }

# ── config ───────────────────────────────────────────────────────────────────
CONFIG="config.yaml"
if [ ! -f "$CONFIG" ]; then
    echo "Error: $CONFIG not found."
    echo "Copy config.example.yaml to config.yaml and fill in your values."
    exit 1
fi

read_config() {
    python3 -c "
import yaml, sys
config = yaml.safe_load(open('$CONFIG'))
keys = sys.argv[1].split('.')
val = config
for k in keys:
    val = val[k]
print(val)
" "$1"
}

FUNCTION_NAME=$(read_config "lambda.function_name")
ROLE_ARN=$(read_config "lambda.role_arn")
REGION=$(read_config "lambda.region" 2>/dev/null || echo "us-east-1")
CONFIG_PROFILE=$(read_config "lambda.profile" 2>/dev/null || echo "")

# CLI --profile overrides config file
PROFILE="${CLI_PROFILE:-$CONFIG_PROFILE}"

# Build common AWS CLI options
AWS_OPTS=(--region "$REGION")
if [ -n "$PROFILE" ]; then
    AWS_OPTS+=(--profile "$PROFILE")
fi

echo "Function : $FUNCTION_NAME"
echo "Role     : $ROLE_ARN"
echo "Region   : $REGION"
[ -n "$PROFILE" ] && echo "Profile  : $PROFILE"
echo ""

# ── generate ACME account key (first run only) ──────────────────────────────
if [ ! -f account.key ]; then
    echo "Generating ACME account key..."
    python3 -c "
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pem = key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
with open('account.key', 'wb') as f:
    f.write(pem)
print('  -> account.key created')
"
fi

# ── build deployment package ─────────────────────────────────────────────────
echo "Building deployment package..."
BUILD_DIR="build"
DIST_DIR="dist"
rm -rf "$BUILD_DIR" "$DIST_DIR"
mkdir -p "$BUILD_DIR" "$DIST_DIR"

python3 -m pip install -r requirements.txt -t "$BUILD_DIR" --quiet \
    --platform manylinux2014_x86_64 \
    --implementation cp \
    --python-version 3.12 \
    --only-binary=:all:

cp handler.py acme_client.py config.yaml account.key "$BUILD_DIR/"

(cd "$BUILD_DIR" && python3 -c "
import zipfile, pathlib
with zipfile.ZipFile('../$DIST_DIR/deployment.zip', 'w', zipfile.ZIP_DEFLATED) as zf:
    for p in sorted(pathlib.Path('.').rglob('*')):
        if p.is_file():
            zf.write(p)
")

PACKAGE_SIZE=$(du -h "$DIST_DIR/deployment.zip" | cut -f1)
echo "  -> $DIST_DIR/deployment.zip ($PACKAGE_SIZE)"
echo ""

# ── deploy Lambda ────────────────────────────────────────────────────────────
if aws lambda get-function --function-name "$FUNCTION_NAME" "${AWS_OPTS[@]}" >/dev/null 2>&1; then
    echo "Updating existing Lambda function..."
    aws lambda update-function-code \
        --function-name "$FUNCTION_NAME" \
        "${AWS_OPTS[@]}" \
        --zip-file "fileb://$DIST_DIR/deployment.zip" \
        --no-cli-pager

    echo "Waiting for update to propagate..."
    aws lambda wait function-updated \
        --function-name "$FUNCTION_NAME" \
        "${AWS_OPTS[@]}"

    aws lambda update-function-configuration \
        --function-name "$FUNCTION_NAME" \
        "${AWS_OPTS[@]}" \
        --role "$ROLE_ARN" \
        --timeout 900 \
        --memory-size 256 \
        --no-cli-pager
else
    echo "Creating new Lambda function..."
    aws lambda create-function \
        --function-name "$FUNCTION_NAME" \
        "${AWS_OPTS[@]}" \
        --role "$ROLE_ARN" \
        --runtime python3.12 \
        --handler handler.lambda_handler \
        --zip-file "fileb://$DIST_DIR/deployment.zip" \
        --timeout 900 \
        --memory-size 256 \
        --no-cli-pager
fi
echo ""

# ── EventBridge schedule (every 21 days) ─────────────────────────────────────
RULE_NAME="${FUNCTION_NAME}-schedule"

echo "Setting up EventBridge schedule (rate: 21 days)..."
aws events put-rule \
    --name "$RULE_NAME" \
    --schedule-expression "rate(21 days)" \
    "${AWS_OPTS[@]}" \
    --state ENABLED \
    --no-cli-pager

LAMBDA_ARN=$(aws lambda get-function \
    --function-name "$FUNCTION_NAME" \
    "${AWS_OPTS[@]}" \
    --query 'Configuration.FunctionArn' \
    --output text)

aws events put-targets \
    --rule "$RULE_NAME" \
    "${AWS_OPTS[@]}" \
    --targets "Id=1,Arn=$LAMBDA_ARN" \
    --no-cli-pager

# Allow EventBridge to invoke the Lambda (idempotent — ignores if already set)
ACCOUNT_ID=$(aws sts get-caller-identity "${AWS_OPTS[@]}" --query Account --output text)
aws lambda add-permission \
    --function-name "$FUNCTION_NAME" \
    "${AWS_OPTS[@]}" \
    --statement-id "${RULE_NAME}-invoke" \
    --action lambda:InvokeFunction \
    --principal events.amazonaws.com \
    --source-arn "arn:aws:events:${REGION}:${ACCOUNT_ID}:rule/${RULE_NAME}" \
    --no-cli-pager 2>/dev/null || true

echo ""
echo "Done! Lambda '$FUNCTION_NAME' deployed and scheduled."
echo ""
echo "To test now:"
echo "  aws lambda invoke --function-name $FUNCTION_NAME ${AWS_OPTS[*]} /dev/stdout"
