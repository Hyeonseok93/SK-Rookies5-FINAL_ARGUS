# ────────────────────────────────────────────────────────────────────────────
# alb.tf
# Application Load Balancer · Target Group · Listener · Routing Rule
#
# 라우팅 정책:
#   HTTP(80)  → HTTPS(443) 301 리다이렉트
#   HTTPS(443) 기본        → frontend TG (Nginx)
#   HTTPS(443) /api/*      → backend TG  (API)
# ────────────────────────────────────────────────────────────────────────────

# ── ALB 본체 (인터넷 노출, 퍼블릭 서브넷 전체 배치) ─────────────────────────
resource "aws_lb" "main" {
  name               = "${var.project_name}-alb"
  internal           = false # Internet-facing
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id # 모든 퍼블릭 서브넷(멀티 AZ)

  enable_deletion_protection = false # 개발/테스트 환경

  tags = {
    Name = "${var.project_name}-alb"
  }
}

# ── 프론트엔드 타겟 그룹 (Nginx) ────────────────────────────────────────────
resource "aws_lb_target_group" "frontend" {
  name     = "${var.project_name}-frontend-tg"
  port     = var.frontend_port
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = var.frontend_health_check_path
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 3
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${var.project_name}-frontend-tg"
  }
}

# ── 백엔드 타겟 그룹 (API / docker-compose) ─────────────────────────────────
resource "aws_lb_target_group" "backend" {
  name     = "${var.project_name}-backend-tg"
  port     = var.backend_port
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = var.backend_health_check_path
    port                = tostring(var.backend_port)
    protocol            = "HTTP"
    matcher             = "200-399"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 3
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${var.project_name}-backend-tg"
  }
}

# ── HTTP(80) 리스너: 전부 HTTPS로 301 리다이렉트 ────────────────────────────
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# ── HTTPS(443) 리스너: ACM 인증서 적용, 기본 → 프론트엔드 TG ────────────────
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.main.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.frontend.arn
  }
}

# ── 라우팅 규칙: /api/* → 백엔드 TG ─────────────────────────────────────────
resource "aws_lb_listener_rule" "api" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.backend.arn
  }

  condition {
    path_pattern {
      values = ["/api/*"]
    }
  }
}
