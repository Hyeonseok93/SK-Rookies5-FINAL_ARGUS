# ────────────────────────────────────────────────────────────────────────────
# backup.tf
# AWS Backup: EBS 볼륨 자동 백업/스냅샷 정책
#
# 대상 선택: provider.tf의 default_tags로 모든 리소스에 Project=<project_name>
# 태그가 자동으로 붙으므로, 그 태그를 기준으로 선택한다. → 개별 파일에서
# 볼륨/인스턴스를 추가할 때 별도 설정 없이 자동으로 백업 대상에 포함된다.
# ────────────────────────────────────────────────────────────────────────────

resource "aws_backup_vault" "main" {
  name = "${var.project_name}-backup-vault"

  tags = {
    Name = "${var.project_name}-backup-vault"
  }
}

resource "aws_backup_plan" "main" {
  name = "${var.project_name}-backup-plan"

  rule {
    rule_name         = "${var.project_name}-daily"
    target_vault_name = aws_backup_vault.main.name
    schedule          = var.backup_schedule_cron

    lifecycle {
      delete_after = var.backup_retention_days
    }
  }

  tags = {
    Name = "${var.project_name}-backup-plan"
  }
}

# ── AWS Backup 서비스가 대신 스냅샷을 뜨기 위한 IAM Role ────────────────────
data "aws_iam_policy_document" "backup_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "backup" {
  name               = "${var.project_name}-backup-role"
  assume_role_policy = data.aws_iam_policy_document.backup_assume.json

  tags = {
    Name = "${var.project_name}-backup-role"
  }
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_iam_role_policy_attachment" "backup_restore" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}

# ── Project 태그 기준으로 백업 대상(EBS 볼륨 등) 자동 선택 ──────────────────
resource "aws_backup_selection" "by_project_tag" {
  name         = "${var.project_name}-by-project-tag"
  plan_id      = aws_backup_plan.main.id
  iam_role_arn = aws_iam_role.backup.arn

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Project"
    value = var.project_name
  }
}
