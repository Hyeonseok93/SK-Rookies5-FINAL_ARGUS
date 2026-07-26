# ────────────────────────────────────────────────────────────────────────────
# variables.tf
# 네트워킹/엣지 계층에서 사용하는 입력 변수 정의
# ────────────────────────────────────────────────────────────────────────────

# ── 공통 ────────────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS 리전"
  type        = string
  default     = "ap-northeast-2"
}

variable "project_name" {
  description = "프로젝트 이름 (리소스 이름 prefix)"
  type        = string
  default     = "argus"
}

variable "environment" {
  description = "배포 환경 (dev / staging / prod)"
  type        = string
  default     = "dev"
}

# ── VPC / Subnet ────────────────────────────────────────────────────────────

variable "vpc_cidr" {
  # Onde(10.0.0.0/16)와 대역을 분리 — 향후 VPC Peering/Transit Gateway 연결 대비
  description = "VPC CIDR 블록 (Onde와 겹치지 않도록 10.1.0.0/16 사용)"
  type        = string
  default     = "10.1.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "퍼블릭 서브넷 CIDR 목록 (ALB + 프론트엔드 EC2 배치)"
  type        = list(string)
  default     = ["10.1.1.0/24", "10.1.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "프라이빗 서브넷 CIDR 목록 (백엔드 EC2 / docker-compose 배치)"
  type        = list(string)
  default     = ["10.1.11.0/24", "10.1.12.0/24"]
}

variable "availability_zones" {
  description = "가용 영역 목록 (public/private 서브넷 수와 일치해야 함)"
  type        = list(string)
  default     = ["ap-northeast-2a", "ap-northeast-2c"]
}

# ── DNS / 인증서 ────────────────────────────────────────────────────────────

variable "domain_name" {
  description = "서비스 루트 도메인 (Route53 호스티드 존 + ACM 인증서 대상)"
  type        = string
  default     = "rookies-argus.click"
}

# ── ALB / 타겟 그룹 ─────────────────────────────────────────────────────────

variable "frontend_port" {
  description = "프론트엔드(Nginx) 리슨 포트"
  type        = number
  default     = 80
}

variable "frontend_instance_type" {
  description = "프론트엔드 EC2 인스턴스 타입"
  type        = string
  default     = "t3.small"
}

variable "frontend_root_volume_size" {
  description = "프론트엔드 EC2 루트 EBS 볼륨 크기(GB)"
  type        = number
  default     = 20

  validation {
    condition     = var.frontend_root_volume_size >= 8
    error_message = "프론트엔드 루트 볼륨은 8GB 이상이어야 합니다."
  }
}

variable "backend_port" {
  description = "백엔드 API(docker-compose) 리슨 포트"
  type        = number
  default     = 8001
}

variable "backend_instance_type" {
  description = "백엔드 EC2 인스턴스 타입 (zap+backend+worker+selenium 4개 컨테이너 동시 구동 기준 추정치 — selenium은 브라우저 구동으로 메모리 소모가 커서 t3.large 이상 권장. 실측 검증 전까지는 잠정값)"
  type        = string
  default     = "t3.large"
}

variable "backend_root_volume_size" {
  description = "백엔드 EC2 루트 EBS 볼륨 크기(GB) — zap/backend/worker/selenium 이미지 저장 공간 포함 (selenium 이미지가 커서 여유있게 산정)"
  type        = number
  default     = 40

  validation {
    condition     = var.backend_root_volume_size >= 8
    error_message = "백엔드 루트 볼륨은 8GB 이상이어야 합니다."
  }
}

variable "frontend_health_check_path" {
  description = "프론트엔드 타겟 그룹 헬스체크 경로"
  type        = string
  default     = "/"
}

variable "backend_health_check_path" {
  description = "백엔드 타겟 그룹 헬스체크 경로 (ARGUS_Merge backend/app/main.py의 @app.get(\"/api/health\") 기준)"
  type        = string
  default     = "/api/health"
}

# ── Storage & Secrets ───────────────────────────────────────────────────────

variable "backend_data_volume_size" {
  description = "백엔드 EC2에 붙일 추가 데이터 EBS 볼륨 크기(GB) — 리포트/redis/docker volume 용도"
  type        = number
  default     = 20
}

variable "reports_expiration_days" {
  description = "리포트 S3 버킷 객체 만료(삭제)까지 걸리는 일수"
  type        = number
  default     = 180
}

variable "reports_ia_transition_days" {
  description = "리포트 S3 버킷 객체를 STANDARD_IA로 전환하는 일수"
  type        = number
  default     = 30
}

variable "tfstate_lock_table_name" {
  description = "Terraform 상태 락용 DynamoDB 테이블 이름"
  type        = string
  default     = "argus-tfstate-lock"
}

variable "app_secret_name" {
  description = "백엔드 애플리케이션 시크릿의 Secrets Manager 이름 (DB/JWT/외부 API 키 등, 실제 값은 콘솔·CLI로 채움)"
  type        = string
  default     = "argus/app"
}

# 아래 3개는 기본값을 두지 않는다 — gitignore된 *.tfvars 파일(예: secrets.auto.tfvars)로만
# 주입해야 하며, 실수로 코드에 실제 값을 박아넣지 못하게 강제한다. (example.tfvars 참고)
variable "db_password" {
  description = "백엔드 DB 비밀번호 (secrets.auto.tfvars 등 gitignore된 파일로 주입)"
  type        = string
  sensitive   = true
}

variable "jwt_secret" {
  description = "백엔드 JWT 서명 시크릿 (secrets.auto.tfvars 등 gitignore된 파일로 주입)"
  type        = string
  sensitive   = true
}

variable "redis_password" {
  description = "Redis 비밀번호 (secrets.auto.tfvars 등 gitignore된 파일로 주입)"
  type        = string
  sensitive   = true
}

variable "github_org" {
  description = "GitHub 조직/계정 이름 (OIDC 신뢰 정책 대상)"
  type        = string
  default     = "UR-ARGUS"
}

variable "github_allowed_repos" {
  description = "GitHub Actions OIDC 역할을 assume 할 수 있는 \"org/repo\" 목록"
  type        = list(string)
  default = [
    "UR-ARGUS/ARGUS_Infra",
    "UR-ARGUS/ARGUS_Merge", # 앱(frontend/backend) CI: lint/test, ECR build&push
  ]
}

variable "backup_schedule_cron" {
  description = "AWS Backup 실행 스케줄 (cron, UTC 기준)"
  type        = string
  default     = "cron(0 18 * * ? *)" # 매일 03:00 KST (UTC 18:00)
}

variable "backup_retention_days" {
  description = "AWS Backup 스냅샷 보관 일수"
  type        = number
  default     = 14
}
