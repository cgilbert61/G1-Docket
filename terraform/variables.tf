variable "aws_region" {
  type        = string
  description = "Target AWS Region for G1 Docket compliance infrastructure"
  default     = "us-east-1"
}

variable "account_id" {
  type        = string
  description = "AWS Account ID"
  default     = "123456789012"
}

variable "environment" {
  type        = string
  description = "Deployment environment (e.g. prod, staging)"
  default     = "prod"
}

variable "retention_years" {
  type        = number
  description = "SEC Rule 17a-4 compliant retention period in years"
  default     = 7
}

variable "bucket_prefix" {
  type        = string
  description = "Prefix for S3 WORM Compliance Ledger bucket"
  default     = "g1-docket-worm-compliance"
}
