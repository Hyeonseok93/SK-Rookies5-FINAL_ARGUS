#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────────────────────
# inject-secrets.sh
# AWS Secrets Manager(argus/app)의 값을 .env 파일로 내려받아
# backend EC2의 docker compose가 참조할 수 있게 한다.
#
# 실행 주체: 백엔드 EC2 (SSM RunCommand로 CD 파이프라인에서 호출)
#   aws ssm send-command \
#     --instance-ids <backend-instance-id> \
#     --document-name "AWS-RunShellScript" \
#     --parameters commands="bash /opt/argus/scripts/inject-secrets.sh"
#
# 필요 권한: 인스턴스 IAM Role에 secretsmanager_read 정책(secrets.tf 참고)이
# attach 되어 있어야 한다.
# ────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SECRET_ID="${SECRET_ID:-argus/app}"
ENV_FILE="${ENV_FILE:-/opt/argus/.env}"
REGION="${AWS_REGION:-ap-northeast-2}"

mkdir -p "$(dirname "$ENV_FILE")"

aws secretsmanager get-secret-value \
  --secret-id "$SECRET_ID" \
  --region "$REGION" \
  --query 'SecretString' \
  --output text |
  python3 -c '
import json, sys
for k, v in json.load(sys.stdin).items():
    print(f"{k}={v}")
' >"$ENV_FILE.tmp"

mv "$ENV_FILE.tmp" "$ENV_FILE"
chmod 600 "$ENV_FILE"

echo "Injected secrets from '$SECRET_ID' into $ENV_FILE"
