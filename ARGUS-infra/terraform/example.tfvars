# ────────────────────────────────────────────────────────────────────────────
# example.tfvars
# 시크릿 변수 주입 예시 (이 파일은 커밋해도 되는 "형식 예시"일 뿐, 실제 값 아님)
#
# 사용법:
#   1) 이 파일을 복사해서 실제 값을 채운다. 파일명은 자유이되 .tfvars로 끝나야
#      .gitignore의 `*.tfvars` 규칙에 걸려 자동으로 커밋에서 제외된다.
#        cp example.tfvars secrets.auto.tfvars
#   2) secrets.auto.tfvars에 실제 값 채워넣기
#   3) *.auto.tfvars는 terraform plan/apply 시 자동 로드된다 (-var-file 불필요)
# ────────────────────────────────────────────────────────────────────────────

db_password     = "changeme-db-password"      # reserved/unused by app
jwt_secret      = "changeme-jwt-secret"
redis_password  = "changeme-redis-password"   # reserved/unused by app
credentials_key = "changeme-credentials-key"
zap_api_key     = "changeme-zap-api-key"
admin_username  = "admin"
admin_password  = "changeme-admin-password"
