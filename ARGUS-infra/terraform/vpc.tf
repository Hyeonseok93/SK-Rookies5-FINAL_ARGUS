# ────────────────────────────────────────────────────────────────────────────
# vpc.tf
# VPC · Subnet · IGW · NAT Gateway · Route Table
# 아키텍처: Public(ALB/Frontend) ↔ Private(Backend) 2-Tier, 2 AZ
# ────────────────────────────────────────────────────────────────────────────

# ── VPC ─────────────────────────────────────────────────────────────────────
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true # VPC 내부 AWS DNS 해석 사용
  enable_dns_hostnames = true # 프라이빗 DNS 호스트네임 부여 (내부 서비스 디스커버리)

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# ── 퍼블릭 서브넷 (인터넷 노출: ALB, 프론트엔드 EC2) ─────────────────────────
resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true # 퍼블릭 IP 자동 할당

  tags = {
    Name = "${var.project_name}-public-${count.index + 1}"
    Tier = "public"
  }
}

# ── 프라이빗 서브넷 (외부 직접 접근 불가: 백엔드 EC2 / docker-compose) ───────
resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name = "${var.project_name}-private-${count.index + 1}"
    Tier = "private"
  }
}

# ── 인터넷 게이트웨이 (Public → 인터넷 양방향) ──────────────────────────────
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

# ── NAT 게이트웨이 (Private → 인터넷 아웃바운드 전용) ────────────────────────
# 비용 절감을 위해 단일 NAT 구성. (prod 고가용성 필요 시 AZ별 1개씩 확장)
resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name = "${var.project_name}-nat-eip"
  }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id # NAT는 반드시 퍼블릭 서브넷에 배치

  depends_on = [aws_internet_gateway.main] # IGW 생성 이후 NAT 생성 보장

  tags = {
    Name = "${var.project_name}-nat"
  }
}

# ── 퍼블릭 라우팅 테이블: 0.0.0.0/0 → IGW ───────────────────────────────────
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ── 프라이빗 라우팅 테이블: 0.0.0.0/0 → NAT ─────────────────────────────────
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = {
    Name = "${var.project_name}-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}
