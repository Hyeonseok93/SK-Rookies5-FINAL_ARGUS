# ────────────────────────────────────────────────────────────────────────────
# security.tf
# 3계층 보안 그룹 (최소 권한 · SG 참조 체인)
#
#   [인터넷] --80/443--> (alb-sg)  --80--> (frontend-sg)  --8001--> (backend-sg)
#                          │                                          ▲
#                          └─────────── /api/* 직접 라우팅 ────────────┘
#
# ※ 각 SG는 CIDR 대신 "앞단 SG"를 source로 참조하여 접근 경로를 강제한다.
# ────────────────────────────────────────────────────────────────────────────

# ── 1) ALB SG: 외부 인터넷 → ALB (80/443) ───────────────────────────────────
resource "aws_security_group" "alb" {
  name        = "${var.project_name}-sg-alb"
  description = "ALB security group for public HTTP/HTTPS access"
  vpc_id      = aws_vpc.main.id

  ingress {
    description      = "HTTP from internet"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description      = "HTTPS from internet"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-alb-sg"
  }
}

# ── 2) Frontend SG: ALB → 프론트엔드(Nginx) only ────────────────────────────
resource "aws_security_group" "frontend" {
  name        = "${var.project_name}-sg-frontend"
  description = "Frontend (Nginx) SG - only ALB can reach it"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Allow ALB to reach frontend"
    from_port       = var.frontend_port
    to_port         = var.frontend_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-frontend-sg"
  }
}

# ── 3) Backend SG: 프론트엔드 → 백엔드 + ALB(/api/*) → 백엔드 ───────────────
# ALB가 /api/* 요청을 백엔드 TG로 직접 forward하므로 alb-sg도 source에 포함.
resource "aws_security_group" "backend" {
  name        = "${var.project_name}-sg-backend"
  description = "Backend API SG - reachable from frontend and ALB only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Allow frontend to reach backend API"
    from_port       = var.backend_port
    to_port         = var.backend_port
    protocol        = "tcp"
    security_groups = [aws_security_group.frontend.id]
  }

  ingress {
    description     = "Allow ALB (/api/*) to reach backend API directly"
    from_port       = var.backend_port
    to_port         = var.backend_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-backend-sg"
  }
}
