# ────────────────────────────────────────────────────────────────────────────
# secrets.tf
# AWS Secrets Manager: 백엔드 애플리케이션 시크릿 (DB/JWT/외부 API 키 등)
#
# ⚠️ 실제 값(비밀번호·키)은 Git에 절대 커밋하지 않는다.
#   db_password/jwt_secret/redis_password 변수는 기본값이 없는 필수(sensitive)
#   변수이며, terraform.tfvars가 아니라 gitignore 처리된 *.tfvars 파일로만 주입한다:
#     1) example.tfvars를 secrets.auto.tfvars로 복사 (파일명은 자유, .tfvars로
#        끝나기만 하면 .gitignore의 `*.tfvars` 규칙에 걸려 자동으로 커밋 제외됨)
#     2) 실제 값 채워넣기
#     3) *.auto.tfvars는 terraform apply 시 자동으로 로드됨 (-var-file 불필요)
#   값은 apply 시점에 Secrets Manager로 올라가고, Terraform state에도 남는다
#   (state는 S3 backend에 암호화 저장 — tfstate.tf 참고).
# ────────────────────────────────────────────────────────────────────────────

resource "aws_secretsmanager_secret" "app" {
  name                    = var.app_secret_name
  description             = "Argus 백엔드 애플리케이션 시크릿 (DB/JWT/외부 API 키 등)"
  recovery_window_in_days = 7 # 실수 삭제 시 7일 내 복구 가능

  tags = {
    Name = "${var.project_name}-app-secret"
  }
}

resource "aws_secretsmanager_secret_version" "app" {
  secret_id = aws_secretsmanager_secret.app.id

  # 실제 키 목록은 백엔드(김어진) 파트와 협의해 확정.
  secret_string = jsonencode({
    DB_PASSWORD    = var.db_password
    JWT_SECRET     = var.jwt_secret
    REDIS_PASSWORD = var.redis_password
  })
}

# ── 백엔드 EC2 Role에서 attach 해서 쓸 수 있는 시크릿 읽기 정책 ─────────────
# 역할 경계: 정책만 정의, 실제 attach는 백엔드 컴퓨트 담당(김어진)이 수행.
resource "aws_iam_policy" "app_secret_read" {
  name        = "${var.project_name}-app-secret-read"
  description = "Argus 애플리케이션 시크릿 읽기 권한 (백엔드 EC2 Role에서 attach)"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadAppSecret"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [aws_secretsmanager_secret.app.arn]
      },
    ]
  })

  tags = {
    Name = "${var.project_name}-app-secret-read"
  }
}
