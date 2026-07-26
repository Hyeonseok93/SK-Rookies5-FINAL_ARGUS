# ────────────────────────────────────────────────────────────────────────────
# acm.tf
# ACM 인증서 발급 + Route53 DNS 검증
#
# 흐름: 인증서 요청 → Route53에 검증용 CNAME 자동 생성 → 검증 완료 대기
#      → 검증된 인증서 ARN을 ALB HTTPS 리스너에서 참조
# ────────────────────────────────────────────────────────────────────────────

# ── 인증서 요청 (루트 + 와일드카드 서브도메인) ──────────────────────────────
resource "aws_acm_certificate" "main" {
  domain_name               = var.domain_name
  subject_alternative_names = ["*.${var.domain_name}"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true # 갱신 시 무중단 교체
  }

  tags = {
    Name = "${var.project_name}-acm"
  }
}

# ── DNS 검증용 레코드 (Route53에 자동 생성) ─────────────────────────────────
resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.main.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  zone_id         = data.aws_route53_zone.main.zone_id
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.record]
  ttl             = 60
  allow_overwrite = true # 루트+와일드카드 검증 레코드가 동일할 때 충돌 방지
}

# ── 검증 완료 대기 (이 리소스 완료 후 리스너에서 인증서 사용) ───────────────
resource "aws_acm_certificate_validation" "main" {
  certificate_arn         = aws_acm_certificate.main.arn
  validation_record_fqdns = [for r in aws_route53_record.cert_validation : r.fqdn]
}
