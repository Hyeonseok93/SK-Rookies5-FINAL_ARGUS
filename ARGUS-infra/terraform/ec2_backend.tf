# ────────────────────────────────────────────────────────────────────────────
# ec2_backend.tf
# Backend Compute: Amazon Linux 2023 · Docker(zap + backend + worker + selenium) · SSM
#
# 요청 흐름:
#   ALB(/api/*) → backend Target Group(:8001) → Backend EC2(:8001)
#
# 운영 흐름:
#   Systems Manager → SSM Agent → Backend EC2
#
# 컨테이너 구성: zap + backend + worker + selenium, 전부 이 EC2 한 대에서
# docker-compose로 기동 (인스턴스를 분리하지 않기로 결정함, 2026-07-21).
# worker/selenium은 아직 ARGUS_Merge docker-compose.yml에 반영 전이라
# 실제 리소스 사용량 기준 스펙 재검증이 필요함 — variables.tf 참고.
# 실제 컨테이너 기동(docker compose up)은 CD 파이프라인(SSM RunCommand)이 담당하며,
# 이 파일은 Docker 런타임 설치, SSM 접속, secrets 주입 스크립트 배치까지만 부트스트랩한다.
# ────────────────────────────────────────────────────────────────────────────

# ── EC2가 사용할 IAM Role (SSM) ──────────────────────────────────────────────
resource "aws_iam_role" "backend_ec2" {
  name = "${var.project_name}-backend-ec2-role"

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
    Name = "${var.project_name}-backend-ec2-role"
  }
}

resource "aws_iam_role_policy_attachment" "backend_ssm" {
  role       = aws_iam_role.backend_ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Storage & Secrets 파트가 정의한 정책(secrets.tf / s3_reports.tf)을 attach.
# 정책 자체는 그쪽 파일 소관, 여기서는 attach만 수행 — 역할 경계는 README 참고.
resource "aws_iam_role_policy_attachment" "backend_secret_read" {
  role       = aws_iam_role.backend_ec2.name
  policy_arn = aws_iam_policy.app_secret_read.arn
}

resource "aws_iam_role_policy_attachment" "backend_reports_s3" {
  role       = aws_iam_role.backend_ec2.name
  policy_arn = aws_iam_policy.reports_s3_access.arn
}

resource "aws_iam_instance_profile" "backend" {
  name = "${var.project_name}-backend-instance-profile"
  role = aws_iam_role.backend_ec2.name
}

# ── Private Subnet의 Backend EC2 ────────────────────────────────────────────
resource "aws_instance" "backend" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = var.backend_instance_type
  subnet_id     = aws_subnet.private[0].id
  # 퍼블릭 IP 미할당 — 아웃바운드는 NAT Gateway 경유, 접속은 SSM만 허용

  vpc_security_group_ids = [aws_security_group.backend.id]
  iam_instance_profile   = aws_iam_instance_profile.backend.name

  # Amazon Linux 2023에는 SSM Agent와 AWS CLI가 기본 설치되어 있다.
  # 실제 backend/zap/worker/selenium 컨테이너는 CD 파이프라인이 SSM으로 docker compose up 실행.
  user_data = <<-EOF
    #!/bin/bash
    set -euxo pipefail

    dnf update -y
    dnf install -y docker python3

    systemctl enable --now docker
    usermod -aG docker ec2-user

    # AL2023 기본 리포지토리엔 docker-compose-plugin 패키지가 없어 공식 릴리스 바이너리로 설치
    mkdir -p /usr/local/lib/docker/cli-plugins
    curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64" \
      -o /usr/local/lib/docker/cli-plugins/docker-compose
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

    # Storage & Secrets 파트가 작성한 secrets 주입 스크립트를 배치.
    # CD가 배포 시 SSM RunCommand로 이 경로를 호출해 Secrets Manager 값을
    # /opt/argus/.env로 내려받는다 (scripts/inject-secrets.sh 헤더 주석 참고).
    mkdir -p /opt/argus/scripts
    echo '${base64encode(replace(file("${path.module}/../scripts/inject-secrets.sh"), "\r\n", "\n"))}' | base64 -d > /opt/argus/scripts/inject-secrets.sh
    chmod +x /opt/argus/scripts/inject-secrets.sh

    systemctl enable amazon-ssm-agent
    systemctl restart amazon-ssm-agent

    # ── 데이터용 EBS 볼륨(20G) 포맷 + 마운트 ──────────────────────────────
    # aws_volume_attachment는 인스턴스 생성 후 별도로 attach되는 리소스라
    # user_data 실행 시점엔 디바이스가 아직 안 붙어있을 수 있다 — 나타날 때까지 대기.
    DEVICE=/dev/nvme1n1
    MOUNT_POINT=/opt/argus/data

    for i in $(seq 1 30); do
      [ -b "$DEVICE" ] && break
      sleep 5
    done

    if [ ! -b "$DEVICE" ]; then
      echo "ERROR: $DEVICE did not appear after waiting" >&2
      exit 1
    fi

    if ! blkid "$DEVICE"; then
      mkfs -t ext4 "$DEVICE"
    fi

    mkdir -p "$MOUNT_POINT"
    mount "$DEVICE" "$MOUNT_POINT"

    UUID=$(blkid -s UUID -o value "$DEVICE")
    grep -q "$MOUNT_POINT" /etc/fstab || echo "UUID=$UUID $MOUNT_POINT ext4 defaults,nofail 0 2" >> /etc/fstab
  EOF

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.backend_root_volume_size
    encrypted             = true
    delete_on_termination = true
  }

  # 인스턴스 메타데이터 접근은 IMDSv2 토큰을 반드시 사용한다.
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  depends_on = [aws_iam_role_policy_attachment.backend_ssm]

  # AMI는 최초 생성 시점 값으로 고정한다 (frontend와 동일한 이유 — ec2_frontend.tf 참고).
  # 고정하지 않으면 AWS가 AL2023 패치 AMI를 새로 릴리스할 때마다 컨테이너가 떠있는
  # 백엔드 인스턴스가 통째로 재생성된다.
  lifecycle {
    ignore_changes = [ami]
  }

  tags = {
    Name = "${var.project_name}-backend"
    Role = "backend"
  }
}

# ── 기존 Backend Target Group에 EC2 등록 ────────────────────────────────────
resource "aws_lb_target_group_attachment" "backend" {
  target_group_arn = aws_lb_target_group.backend.arn
  target_id        = aws_instance.backend.id
  port             = var.backend_port
}

# ── Storage & Secrets가 정의한 데이터 볼륨(ebs.tf)을 이 인스턴스에 연결 ──────
# 볼륨 리소스 정의는 ebs.tf 소관, attachment는 README에 명시된 대로 컴퓨트 파트가 수행.
#
# 주의: t3(Nitro 기반) 인스턴스는 device_name("/dev/xvdf")이 AWS API상의 요청값일 뿐,
# 실제 OS 안에서는 /dev/nvme1n1 등으로 보인다. CD/운영 스크립트에서 마운트할 때는
# device_name을 직접 쓰지 말고 `lsblk`/`nvme list`로 실제 디바이스를 확인해야 한다.
resource "aws_volume_attachment" "backend_data" {
  device_name = "/dev/xvdf"
  volume_id   = aws_ebs_volume.backend_data.id
  instance_id = aws_instance.backend.id
}
