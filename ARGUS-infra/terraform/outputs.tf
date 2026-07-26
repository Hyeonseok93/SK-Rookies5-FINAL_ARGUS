# ────────────────────────────────────────────────────────────────────────────
# outputs.tf
# ────────────────────────────────────────────────────────────────────────────

# ── VPC / Subnet ────────────────────────────────────────────────────────────
output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "퍼블릭 서브넷 ID 목록 (ALB / 프론트엔드 EC2 배치)"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "프라이빗 서브넷 ID 목록 (백엔드 EC2 배치)"
  value       = aws_subnet.private[*].id
}

# ── Security Group ──────────────────────────────────────────────────────────
output "alb_security_group_id" {
  description = "ALB 보안 그룹 ID"
  value       = aws_security_group.alb.id
}

output "frontend_security_group_id" {
  description = "프론트엔드 EC2 보안 그룹 ID (박진아 파트에서 참조)"
  value       = aws_security_group.frontend.id
}

output "backend_security_group_id" {
  description = "백엔드 EC2 보안 그룹 ID (김어진 파트에서 참조)"
  value       = aws_security_group.backend.id
}

# ── ALB / Target Group ──────────────────────────────────────────────────────
output "alb_dns_name" {
  description = "ALB DNS 이름"
  value       = aws_lb.main.dns_name
}

output "alb_zone_id" {
  description = "ALB Route53 Zone ID (Alias 레코드용)"
  value       = aws_lb.main.zone_id
}

output "frontend_target_group_arn" {
  description = "프론트엔드 타겟 그룹 ARN"
  value       = aws_lb_target_group.frontend.arn
}

output "backend_target_group_arn" {
  description = "백엔드 타겟 그룹 ARN"
  value       = aws_lb_target_group.backend.arn
}

# ── Frontend Compute ────────────────────────────────────────────────────────
output "frontend_instance_id" {
  description = "프론트엔드 EC2 인스턴스 ID (SSM/CI/CD 배포 대상)"
  value       = aws_instance.frontend.id
}

output "frontend_private_ip" {
  description = "프론트엔드 EC2 프라이빗 IP"
  value       = aws_instance.frontend.private_ip
}

output "frontend_public_ip" {
  description = "프론트엔드 EC2 퍼블릭 IP"
  value       = aws_instance.frontend.public_ip
}

output "frontend_iam_role_name" {
  description = "프론트엔드 EC2 SSM IAM Role 이름"
  value       = aws_iam_role.frontend_ec2.name
}

# ── Backend Compute ─────────────────────────────────────────────────────────
output "backend_instance_id" {
  description = "백엔드 EC2 인스턴스 ID (SSM/CI/CD 배포 대상)"
  value       = aws_instance.backend.id
}

output "backend_private_ip" {
  description = "백엔드 EC2 프라이빗 IP"
  value       = aws_instance.backend.private_ip
}

output "backend_iam_role_name" {
  description = "백엔드 EC2 IAM Role 이름 (SSM + Storage&Secrets가 요청한 app_secret_read/reports_s3_access 정책)"
  value       = aws_iam_role.backend_ec2.name
}

# ── DNS / ACM ───────────────────────────────────────────────────────────────
output "route53_zone_id" {
  description = "Route53 호스티드 존 ID (참조)"
  value       = data.aws_route53_zone.main.zone_id
}

output "route53_name_servers" {
  description = "호스티드 존 네임서버 (Route53 등록 도메인이라 자동 연결됨)"
  value       = data.aws_route53_zone.main.name_servers
}

output "acm_certificate_arn" {
  description = "검증 완료된 ACM 인증서 ARN"
  value       = aws_acm_certificate_validation.main.certificate_arn
}

output "service_url" {
  description = "서비스 접속 URL"
  value       = "https://${var.domain_name}"
}

# ── Storage & Secrets ───────────────────────────────────────────────────────
output "tfstate_bucket_name" {
  description = "Terraform 원격 상태 저장용 S3 버킷 이름 (provider.tf backend 블록에 사용)"
  value       = aws_s3_bucket.tfstate.bucket
}

output "tfstate_lock_table_name" {
  description = "Terraform 상태 락용 DynamoDB 테이블 이름"
  value       = aws_dynamodb_table.tfstate_lock.name
}

output "reports_bucket_name" {
  description = "ZAP·Selenium 리포트 저장용 S3 버킷 이름"
  value       = aws_s3_bucket.reports.bucket
}

output "reports_bucket_arn" {
  description = "리포트 S3 버킷 ARN"
  value       = aws_s3_bucket.reports.arn
}

output "reports_s3_access_policy_arn" {
  description = "리포트 버킷 읽기/쓰기 IAM 정책 ARN (백엔드·CD Role에 attach)"
  value       = aws_iam_policy.reports_s3_access.arn
}

output "backend_data_volume_id" {
  description = "백엔드 데이터 EBS 볼륨 ID (백엔드 컴퓨트 파트에서 aws_volume_attachment로 연결)"
  value       = aws_ebs_volume.backend_data.id
}

output "app_secret_arn" {
  description = "백엔드 애플리케이션 시크릿(Secrets Manager) ARN"
  value       = aws_secretsmanager_secret.app.arn
}

output "app_secret_read_policy_arn" {
  description = "애플리케이션 시크릿 읽기 IAM 정책 ARN (백엔드 EC2 Role에 attach)"
  value       = aws_iam_policy.app_secret_read.arn
}

output "github_actions_role_arn" {
  description = "GitHub Actions가 OIDC로 assume 할 IAM Role ARN (워크플로우의 role-to-assume 값)"
  value       = aws_iam_role.github_actions.arn
}

output "github_oidc_provider_arn" {
  description = "GitHub Actions OIDC Provider ARN"
  value       = aws_iam_openid_connect_provider.github_actions.arn
}

output "backup_vault_name" {
  description = "AWS Backup Vault 이름"
  value       = aws_backup_vault.main.name
}

# ── ECR Repositories ────────────────────────────────────────────────────────
output "ecr_repository_frontend_url" {
  description = "프론트엔드 ECR 리포지토리 URL"
  value       = aws_ecr_repository.frontend.repository_url
}

output "ecr_repository_backend_url" {
  description = "백엔드 ECR 리포지토리 URL"
  value       = aws_ecr_repository.backend.repository_url
}
