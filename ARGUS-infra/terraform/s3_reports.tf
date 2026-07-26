# ────────────────────────────────────────────────────────────────────────────
# s3_reports.tf
# ZAP·Selenium 진단 리포트 저장용 S3 버킷
#
# 쓰기: 백엔드 EC2(worker/zap/selenium 컨테이너) → 리포트 업로드
# 읽기: CD 파트(김현석) → 배포 검증 시 리포트 조회
# ────────────────────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "reports" {
  bucket = "${var.project_name}-reports-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "${var.project_name}-reports"
  }
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── 오래된 리포트 자동 정리 (비용 절감) ──────────────────────────────────────
resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "expire-old-reports"
    status = "Enabled"

    filter {}

    transition {
      days          = var.reports_ia_transition_days
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = var.reports_expiration_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.reports_ia_transition_days
    }
  }
}

# ── 백엔드/CI/CD 파트가 attach 해서 쓸 수 있는 리포트 버킷 접근 정책 ─────────
# 역할 경계: 정책(policy)만 정의. 실제 IAM Role에 attach하는 것은 각 파트 담당.
resource "aws_iam_policy" "reports_s3_access" {
  name        = "${var.project_name}-reports-s3-access"
  description = "Argus 리포트 S3 버킷 읽기/쓰기 권한 (백엔드·CD 파트에서 각자 Role에 attach)"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ListReportsBucket"
        Effect = "Allow"
        Action = ["s3:ListBucket"]
        Resource = [
          aws_s3_bucket.reports.arn
        ]
      },
      {
        Sid    = "ReadWriteReportsObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
        ]
        Resource = [
          "${aws_s3_bucket.reports.arn}/*"
        ]
      },
    ]
  })

  tags = {
    Name = "${var.project_name}-reports-s3-access"
  }
}
