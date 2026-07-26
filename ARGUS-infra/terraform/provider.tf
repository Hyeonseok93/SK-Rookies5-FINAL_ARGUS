# ────────────────────────────────────────────────────────────────────────────
# provider.tf
# Terraform / AWS Provider 설정
# ────────────────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.3.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # ── 원격 상태 저장소 (S3 + DynamoDB 락) ───────────────────────────────────
  # ⚠️ 반드시 Argus 전용 버킷/락 테이블을 새로 생성해서 사용할 것.
  #    Onde의 onde-tfstate-bucket-802314158104 / onde-tfstate-lock 을 절대 재사용 금지.
  #    (같은 state를 공유하면 apply 시 서로의 리소스를 삭제/덮어쓸 수 있음)
  #    버킷/락 리소스는 Storage & Secrets 담당(장성욱)이 생성 후 아래 값 채워 활성화.
  #    리소스 정의: tfstate.tf (aws_s3_bucket.tfstate / aws_dynamodb_table.tfstate_lock)
  #    부트스트랩 절차(로컬 상태 → S3로 migrate)도 tfstate.tf 상단 주석 참고.
  # backend "s3" {
  #   bucket         = "argus-tfstate-bucket-<AWS_ACCOUNT_ID>"  # Argus 전용 버킷
  #   key            = "terraform/state.tfstate"
  #   region         = "ap-northeast-2"
  #   dynamodb_table = "argus-tfstate-lock"                     # Argus 전용 락 테이블
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  # Terraform으로 생성하는 모든 리소스에 공통 태그 자동 부착
  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = "networking-edge"
    }
  }
}
