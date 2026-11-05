terraform {
  required_version = ">= 1.5.0"
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

# 1. Dedicated KMS Customer Managed Key (CMK) for WORM Ledger & DSSE Envelopes
resource "aws_kms_key" "docket_ledger_key" {
  description             = "KMS CMK for G1 Docket Cryptographic WORM Ledger"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Docket Services Envelope Encryption"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.docket_k8s_service_role.arn
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Environment = var.environment
    Application = "G1-Docket"
    Compliance  = "SEC-17a-4-WORM"
  }
}

resource "aws_kms_alias" "docket_ledger_key_alias" {
  name          = "alias/g1-docket-worm-${var.environment}"
  target_key_id = aws_kms_key.docket_ledger_key.key_id
}

# 2. Immutable S3 Bucket with Mandatory Object Lock in COMPLIANCE Mode
resource "aws_s3_bucket" "worm_ledger" {
  bucket        = "${var.bucket_prefix}-${var.environment}-${var.account_id}"
  force_destroy = false # Prevent accidental destruction of regulatory audit records

  object_lock_enabled = true

  tags = {
    Environment = var.environment
    Application = "G1-Docket"
    Compliance  = "SEC-17a-4-WORM"
    Regulatory  = "EU-AI-Act-Art10"
  }
}

# Enforce Versioning (Required by S3 Object Lock)
resource "aws_s3_bucket_versioning" "worm_ledger_versioning" {
  bucket = aws_s3_bucket.worm_ledger.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Default Object Lock Configuration: COMPLIANCE Mode (Non-erasable even by root/admin)
resource "aws_s3_bucket_object_lock_configuration" "worm_compliance_rule" {
  bucket = aws_s3_bucket.worm_ledger.id

  rule {
    default_retention {
      mode  = "COMPLIANCE"
      years = var.retention_years
    }
  }
}

# Enforce Server-Side Encryption with KMS CMK
resource "aws_s3_bucket_server_side_encryption_configuration" "worm_encryption" {
  bucket = aws_s3_bucket.worm_ledger.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.docket_ledger_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Block All Public Access
resource "aws_s3_bucket_public_access_block" "worm_public_block" {
  bucket = aws_s3_bucket.worm_ledger.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 3. IAM Role for Kubernetes Service Account (IRSA)
resource "aws_iam_role" "docket_k8s_service_role" {
  name = "g1-docket-service-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${var.account_id}:oidc-provider/oidc.eks.${var.aws_region}.amazonaws.com/id/EXAMPLE"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "oidc.eks.${var.aws_region}.amazonaws.com/id/EXAMPLE:sub" = "system:serviceaccount:g1-docket-system:g1-docket-sa"
          }
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
    Application = "G1-Docket"
  }
}

resource "aws_iam_policy" "docket_s3_policy" {
  name        = "g1-docket-s3-compliance-policy-${var.environment}"
  description = "Allows writing WORM records and reading verified envelopes"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowWORMWrite"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:GetObjectVersion",
          "s3:GetObjectRetention",
          "s3:PutObjectRetention"
        ]
        Resource = [
          aws_s3_bucket.worm_ledger.arn,
          "${aws_s3_bucket.worm_ledger.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "docket_attach_s3" {
  role       = aws_iam_role.docket_k8s_service_role.name
  policy_arn = aws_iam_policy.docket_s3_policy.arn
}
