# ────────────────────────────────────────────────────────────────────────────
# ec2_frontend.tf
# Frontend Compute: Amazon Linux 2023 · Docker/Nginx · SSM
#
# 요청 흐름:
#   ALB → frontend Target Group(:80) → Frontend EC2(:80)
#
# 운영 흐름:
#   Systems Manager → SSM Agent → Frontend EC2
# ────────────────────────────────────────────────────────────────────────────

# ── Amazon Linux 2023 최신 x86_64 AMI 조회 ──────────────────────────────────
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ── EC2가 사용할 SSM IAM Role ───────────────────────────────────────────────
resource "aws_iam_role" "frontend_ec2" {
  name = "${var.project_name}-frontend-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-frontend-ec2-role"
  }
}

resource "aws_iam_role_policy_attachment" "frontend_ssm" {
  role       = aws_iam_role.frontend_ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "frontend" {
  name = "${var.project_name}-frontend-instance-profile"
  role = aws_iam_role.frontend_ec2.name
}

# ── Public Subnet의 Frontend EC2 ────────────────────────────────────────────
resource "aws_instance" "frontend" {
  ami                         = data.aws_ami.amazon_linux_2023.id
  instance_type               = var.frontend_instance_type
  subnet_id                   = aws_subnet.public[0].id
  associate_public_ip_address = true

  vpc_security_group_ids = [aws_security_group.frontend.id]
  iam_instance_profile   = aws_iam_instance_profile.frontend.name

  # Amazon Linux 2023에는 SSM Agent와 AWS CLI가 기본 설치되어 있다.
  # 실제 Nginx는 ARGUS frontend Docker 이미지 안에서 실행한다.
  user_data = <<-EOF
    #!/bin/bash
    set -euxo pipefail

    dnf update -y
    dnf install -y docker

    systemctl enable --now docker
    usermod -aG docker ec2-user

    systemctl enable amazon-ssm-agent
    systemctl restart amazon-ssm-agent
  EOF

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.frontend_root_volume_size
    encrypted             = true
    delete_on_termination = true
  }

  # 인스턴스 메타데이터 접근은 IMDSv2 토큰을 반드시 사용한다.
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  depends_on = [aws_iam_role_policy_attachment.frontend_ssm]

  # AMI는 최초 생성 시점 값으로 고정한다.
  # data.aws_ami가 most_recent = true라서, 고정하지 않으면 AWS가 AL2023 패치 AMI를
  # 새로 릴리스할 때마다 plan에서 인스턴스가 매번 재생성(다운타임)된다.
  lifecycle {
    ignore_changes = [ami]
  }

  tags = {
    Name = "${var.project_name}-frontend"
    Role = "frontend"
  }
}

# ── 기존 Frontend Target Group에 EC2 등록 ──────────────────────────────────
resource "aws_lb_target_group_attachment" "frontend" {
  target_group_arn = aws_lb_target_group.frontend.arn
  target_id        = aws_instance.frontend.id
  port             = var.frontend_port
}
