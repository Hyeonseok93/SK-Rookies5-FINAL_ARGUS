# ────────────────────────────────────────────────────────────────────────────
# ecr.tf
# Container Image Registry: Amazon ECR
# ────────────────────────────────────────────────────────────────────────────

# ── Frontend ECR Repository ─────────────────────────────────────────────────
resource "aws_ecr_repository" "frontend" {
  name                 = "${var.project_name}-${var.environment}-frontend"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-frontend"
    Environment = var.environment
  }
}

# ── Backend ECR Repository ──────────────────────────────────────────────────
resource "aws_ecr_repository" "backend" {
  name                 = "${var.project_name}-${var.environment}-backend"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-backend"
    Environment = var.environment
  }
}

# ── ECR Lifecycle Policy ────────────────────────────────────────────────────
# untagged 이미지는 7일 후 삭제, 전체 이미지는 최근 30개만 유지 (예시)
resource "aws_ecr_lifecycle_policy" "frontend_policy" {
  repository = aws_ecr_repository.frontend.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images older than 7 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 7
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Keep last 30 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 30
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

resource "aws_ecr_lifecycle_policy" "backend_policy" {
  repository = aws_ecr_repository.backend.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images older than 7 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 7
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Keep last 30 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 30
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# ── ECR Pull 권한 (배포 대상 EC2가 이미지를 받아가기 위함) ──────────────────
# push는 github_oidc.tf의 github_actions role만 담당하고, 이 정책은 pull 전용.
# docker-compose.prod.yml이 두 EC2에서 ECR 이미지를 pull하려면 필요.
resource "aws_iam_policy" "ecr_pull" {
  name = "${var.project_name}-ecr-pull"

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
        Sid    = "EcrPull"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
        ]
        Resource = [
          aws_ecr_repository.frontend.arn,
          aws_ecr_repository.backend.arn,
        ]
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "frontend_ecr_pull" {
  role       = aws_iam_role.frontend_ec2.name
  policy_arn = aws_iam_policy.ecr_pull.arn
}

resource "aws_iam_role_policy_attachment" "backend_ecr_pull" {
  role       = aws_iam_role.backend_ec2.name
  policy_arn = aws_iam_policy.ecr_pull.arn
}
