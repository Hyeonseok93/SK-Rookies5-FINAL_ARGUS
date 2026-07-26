# ────────────────────────────────────────────────────────────────────────────
# dns.tf
# Route53 호스티드 존(참조) + 서비스 도메인 A(Alias) 레코드
#
# ※ 도메인(rookies-argus.click)을 AWS Route53에서 등록할 때 호스티드 존이
#   자동 생성되므로, TF는 존을 새로 만들지 않고 기존 존을 data로 참조한다.
#   (존을 또 만들면 같은 이름의 호스티드 존이 중복되어 NS가 어긋남)
# ────────────────────────────────────────────────────────────────────────────

data "aws_route53_zone" "main" {
  name         = var.domain_name
  private_zone = false
}

# ── 루트 도메인 → ALB Alias ─────────────────────────────────────────────────
resource "aws_route53_record" "root" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}

# ── www 서브도메인 → ALB Alias ──────────────────────────────────────────────
resource "aws_route53_record" "www" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "www.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}
