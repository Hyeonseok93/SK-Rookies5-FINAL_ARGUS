# ────────────────────────────────────────────────────────────────────────────
# github_oidc.tf
# GitHub Actions ↔ AWS OIDC 연동 (장기 액세스 키 없이 CI/CD가 AWS 자격 증명을 획득)
#
# 대상: CI(홍지호) - 이미지 빌드/ECR push, terraform plan
#       CD(김현석) - SSM 배포, HTTP/ALB 헬스 검증
# 흐용: GitHub Actions → OIDC 토큰 발급 → sts:AssumeRoleWithWebIdentity
#      → var.github_allowed_repos 에 등록된 리포지토리만 Role 획득 가능
# ────────────────────────────────────────────────────────────────────────────

data "tls_certificate" "github_actions" {
  url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
}

resource "aws_iam_openid_connect_provider" "github_actions" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github_actions.certificates[0].sha1_fingerprint]

  tags = {
    Name = "${var.project_name}-github-oidc"
  }
}

# ── GitHub Actions가 assume 할 IAM Role ─────────────────────────────────────
data "aws_iam_policy_document" "github_actions_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # 등록된 리포지토리의 모든 브랜치/태그/PR에서 assume 허용 (org/repo:*)
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [for repo in var.github_allowed_repos : "repo:${repo}:*"]
    }
  }
}

resource "aws_iam_role" "github_actions" {
  name               = "${var.project_name}-github-actions-role"
  assume_role_policy = data.aws_iam_policy_document.github_actions_assume.json

  tags = {
    Name = "${var.project_name}-github-actions-role"
  }
}

# ── ECR push/pull (CI 이미지 빌드) ──────────────────────────────────────────
resource "aws_iam_role_policy" "github_actions_ecr" {
  name = "${var.project_name}-github-actions-ecr"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "EcrAuth"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "EcrPushPull"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
        ]
        Resource = "arn:aws:ecr:${var.aws_region}:${data.aws_caller_identity.current.account_id}:repository/${var.project_name}-*"
      },
    ]
  })
}

# ── tfstate 접근 (terraform plan/apply 실행) ────────────────────────────────
resource "aws_iam_role_policy" "github_actions_tfstate" {
  name = "${var.project_name}-github-actions-tfstate"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "TfstateBucket"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = [aws_s3_bucket.tfstate.arn]
      },
      {
        Sid      = "TfstateObject"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = ["${aws_s3_bucket.tfstate.arn}/*"]
      },
      {
        Sid      = "TfstateLock"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
        Resource = [aws_dynamodb_table.tfstate_lock.arn]
      },
    ]
  })
}

# ── SSM 배포 + 배포 검증 (CD: RunCommand / 인스턴스·TG 헬스) ────────────────
# CloudWatch/Synthetics 미사용 — HTTP smoke + DescribeTargetHealth 로 검증.
resource "aws_iam_role_policy" "github_actions_ssm_deploy" {
  name = "${var.project_name}-github-actions-ssm-deploy"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SsmDeploy"
        Effect = "Allow"
        Action = [
          "ssm:SendCommand",
          "ssm:GetCommandInvocation",
          "ssm:ListCommandInvocations",
          "ssm:DescribeInstanceInformation",
        ]
        Resource = "*"
      },
      {
        Sid    = "Ec2DescribeForCd"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
        ]
        Resource = "*"
      },
      {
        Sid    = "AlbTargetHealthForCd"
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:DescribeTargetGroups",
        ]
        Resource = "*"
      },
    ]
  })
}

# ── 리포트 S3 접근 (배포 검증 시 ZAP/Selenium 리포트 조회) ──────────────────
resource "aws_iam_role_policy_attachment" "github_actions_reports" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.reports_s3_access.arn
}
