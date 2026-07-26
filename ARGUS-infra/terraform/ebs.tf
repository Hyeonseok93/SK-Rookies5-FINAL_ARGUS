# ────────────────────────────────────────────────────────────────────────────
# ebs.tf
# 백엔드용 추가 데이터 EBS 볼륨 (redis 영속 데이터 / docker volume / 리포트 임시 저장)
#
# 역할 경계 (outputs 참고): 이 파일은 볼륨 리소스만 "정의"한다.
# 실제 EC2에 붙이는 attachment는 백엔드 컴퓨트 담당(김어진)이 ec2_backend.tf에서
# aws_volume_attachment 로 output.backend_data_volume_id 를 참조해 연결한다.
#
#   resource "aws_volume_attachment" "backend_data" {
#     device_name = "/dev/xvdf"
#     volume_id   = data.terraform_remote_state... (또는 output 참조)
#     instance_id = aws_instance.backend.id
#   }
# ────────────────────────────────────────────────────────────────────────────

resource "aws_ebs_volume" "backend_data" {
  availability_zone = var.availability_zones[0] # 백엔드 프라이빗 서브넷[0]과 동일 AZ
  size              = var.backend_data_volume_size
  type              = "gp3"
  encrypted         = true

  tags = {
    Name = "${var.project_name}-backend-data"
    Role = "backend-data"
  }
}
