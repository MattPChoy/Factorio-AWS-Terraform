terraform {
  required_version = ">= 1.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ---------- Variables ----------
variable "aws_region" {
  type    = string
  default = "ap-southeast-2"
}
variable "project_name" {
  type    = string
  default = "factorio-ecs-nlb"
}
variable "desired_count" {
  type    = number
  default = 1
}
variable "fargate_cpu" {
  type    = string
  default = "1024"
}
variable "fargate_memory" {
  type    = string
  default = "2048"
}
variable "factorio_port" {
  type    = number
  default = 34197
}
# ---------- Networking ----------
data "aws_availability_zones" "azs" {}

resource "aws_vpc" "main" {
  cidr_block           = "10.100.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = { Name = "${var.project_name}-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project_name}-igw" }
}

resource "aws_subnet" "public" {
  count                   = 1
  vpc_id                  = aws_vpc.main.id
  cidr_block = cidrsubnet(aws_vpc.main.cidr_block, 8, 0)
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.azs.names[0]
  tags = { Name = "${var.project_name}-public-${count.index}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "${var.project_name}-public-rt" }
}

resource "aws_route_table_association" "public_assoc" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ---------- Security ----------
resource "aws_security_group" "ecs_sg" {
  name        = "${var.project_name}-sg"
  vpc_id      = aws_vpc.main.id
  description = "Allow Factorio UDP port and control access"

  # Factorio UDP port open to the world (adjust as required)
  ingress {
    description      = "Factorio UDP"
    from_port        = var.factorio_port
    to_port          = var.factorio_port
    protocol         = "udp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  # (Optional) allow health checks (TCP) from the NLB's healthcheck — NLB uses ephemeral source, allow all outbound/ingress for TCP healthcheck
  ingress {
    description = "TCP healthcheck"
    from_port   = var.factorio_port
    to_port     = var.factorio_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-sg" }
}

# ---------- ECS Cluster & IAM ----------
resource "aws_ecs_cluster" "this" {
  name = "${var.project_name}-cluster"
}

resource "aws_iam_role" "ecs_task_execution" {
  name = "${var.project_name}-task-exec-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
}

data "aws_iam_policy_document" "ecs_task_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "exec_attach" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ---------- CloudWatch Logs ----------
resource "aws_cloudwatch_log_group" "factorio" {
  name              = "/ecs/${var.project_name}"
  retention_in_days = 14
}

# ---------- ECS Task Definition ----------
# NOTE: This example uses the community image "factoriotools/factorio:latest".
# If the image requires additional configuration (licenses, save files), mount a volume or EFS as needed.
locals {
  container_definitions = jsonencode([
    {
      name  = "factorio"
      image = "factoriotools/factorio:2.0.60"
      # The container must expose the UDP port for Factorio multiplayer
      portMappings = [
        {
          containerPort = var.factorio_port
          protocol      = "udp"
        }
      ]
      essential = true
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.factorio.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "factorio"
        }
      }
      # Adjust env / mountPoints / command as required by the specific image/version
    }
  ])
}

resource "aws_ecs_task_definition" "factorio" {
  family                   = "${var.project_name}-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.fargate_cpu
  memory                   = var.fargate_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  container_definitions    = local.container_definitions
}

# ---------- NLB ----------
resource "aws_lb" "nlb" {
  name               = "${var.project_name}-nlb"
  internal           = false
  load_balancer_type = "network"
  subnets            = [for s in aws_subnet.public : s.id]
  enable_deletion_protection = false
  tags = { Name = "${var.project_name}-nlb" }
}

# Target group -> UDP protocol, target_type = "ip" for Fargate
resource "aws_lb_target_group" "factorio_udp_tg" {
  name        = "${var.project_name}-udp-tg"
  port        = var.factorio_port
  protocol    = "UDP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  # NLB health checks for UDP need to be TCP/HTTP; use TCP health check against same port.
  health_check {
    enabled             = true
    protocol            = "TCP"
    port                = tostring(var.factorio_port)
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
    timeout             = 5
  }
}

resource "aws_lb_listener" "udp_listener" {
  load_balancer_arn = aws_lb.nlb.arn
  port              = var.factorio_port
  protocol          = "UDP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.factorio_udp_tg.arn
  }
}

# ---------- ECS Service ----------
resource "aws_ecs_service" "factorio" {
  name            = "${var.project_name}-service"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.factorio.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = [for s in aws_subnet.public : s.id]
    security_groups = [aws_security_group.ecs_sg.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.factorio_udp_tg.arn
    container_name   = "factorio"
    container_port   = var.factorio_port
  }

  depends_on = [aws_lb_listener.udp_listener]
}

# ---------- Outputs ----------
output "nlb_dns_name" {
  description = "Network Load Balancer DNS — connect clients to this UDP port"
  value       = aws_lb.nlb.dns_name
}

output "ecs_cluster" {
  value = aws_ecs_cluster.this.name
}

output "ecs_service" {
  value = aws_ecs_service.factorio.name
}

output "public_subnet_ids" {
  value = [for s in aws_subnet.public : s.id]
}

output "notes" {
  value = <<EOT
Direct connect:
- The Fargate task will get a public IP (awsvpc + assign_public_ip = true). Find it in the console (ECS -> Tasks -> ENI) or via: aws ecs describe-tasks / aws ec2 describe-network-interfaces.
NLB connect:
- Use the NLB DNS name (${aws_lb.nlb.dns_name}) and UDP port ${var.factorio_port}.

Security:
- This example opens UDP 34197 to the world. Lock to your IP ranges for safety.
EOT
}


