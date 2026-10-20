# Sentinel demo: deliberately insecure resources.
#
# Everything here is harmless on purpose:
#   - the security group is attached to nothing, so no traffic can reach anything
#   - the bucket is empty, so there is nothing to read
# Never put real data in this bucket or attach this security group to a server.
#
# This folder is applied by hand and uses local state, separate from the main stack.

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "region" {
  type    = string
  default = "eu-north-1"
}

provider "aws" {
  region = var.region
}

data "aws_vpc" "default" {
  default = true
}

# SG-001 (SSH open to the internet) and SG-002 (database port open to the internet)
resource "aws_security_group" "demo_open" {
  name_prefix = "sentinel-demo-open-"
  description = "Sentinel demo: deliberately open and attached to nothing"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH open to the world (demo)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "MySQL open to the world (demo)"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Purpose = "sentinel-demo"
  }
}

# S3-001 (Block Public Access off) and S3-002 (policy allows public access)
resource "aws_s3_bucket" "demo_public" {
  bucket_prefix = "sentinel-demo-"
  force_destroy = true

  tags = {
    Purpose = "sentinel-demo"
  }
}

resource "aws_s3_bucket_public_access_block" "demo_public" {
  bucket = aws_s3_bucket.demo_public.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "demo_public" {
  bucket     = aws_s3_bucket.demo_public.id
  depends_on = [aws_s3_bucket_public_access_block.demo_public]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.demo_public.arn}/*"
    }]
  })
}