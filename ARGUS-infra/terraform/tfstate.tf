# ────────────────────────────────────────────────────────────────────────────
# tfstate.tf
# Terraform 원격 상태 저장소 부트스트랩: S3(상태 파일) + DynamoDB(락)
#
# ⚠️ 닭이 먼저냐 달걀이 먼저냐 문제:
#   이 리소스들 자체는 "이 리소스들을 저장할 원격 상태"가 아직 없는 로컬 상태로
#   최초 1회 생성해야 한다. 순서:
#     1) provider.tf의 backend "s3" 블록이 주석인 상태에서 `terraform apply`
#        → 로컬(terraform.tfstate)에 이 버킷/테이블이 생성됨
#     2) provider.tf의 backend "s3" 블록 주석 해제 (버킷 이름은 아래와 동일한
#        argus-tfstate-bucket-<AWS_ACCOUNT_ID> 규칙)
#     3) `terraform init -migrate-state` 실행 → 로컬 상태를 방금 만든 S3로 이전
#
#   절대 Onde의 tfstate 버킷/락 테이블을 재사용하지 말 것 (provider.tf 참고).
# ────────────────────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}

# ── tfstate 저장용 S3 버킷 ───────────────────────────────────────────────────
resource "aws_s3_bucket" "tfstate" {
  bucket = "${var.project_name}-tfstate-bucket-${data.aws_caller_identity.current.account_id}"

  # 실수로 상태 파일 버킷이 삭제되는 것을 방지 (전체 인프라 상태 유실 위험)
  lifecycle {
    prevent_destroy = true
  }

  tags = {
    Name = "${var.project_name}-tfstate-bucket"
  }
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  versioning_configuration {
    status = "Enabled" # 상태 파일 손상/오적용 시 이전 버전으로 롤백 가능
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── 상태 락(Lock)용 DynamoDB 테이블 ─────────────────────────────────────────
resource "aws_dynamodb_table" "tfstate_lock" {
  name         = var.tfstate_lock_table_name
  billing_mode = "PAY_PER_REQUEST" # 트래픽이 적으므로 온디맨드로 비용 절감
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    Name = var.tfstate_lock_table_name
  }
}
