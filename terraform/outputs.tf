output "kms_key_arn" {
  description = "ARN of KMS Customer Managed Key for WORM Ledger"
  value       = aws_kms_key.docket_ledger_key.arn
}

output "kms_key_id" {
  description = "Key ID of KMS Customer Managed Key"
  value       = aws_kms_key.docket_ledger_key.key_id
}

output "s3_worm_bucket_name" {
  description = "Name of the S3 WORM Compliance Ledger bucket"
  value       = aws_s3_bucket.worm_ledger.id
}

output "s3_worm_bucket_arn" {
  description = "ARN of the S3 WORM Compliance Ledger bucket"
  value       = aws_s3_bucket.worm_ledger.arn
}

output "iam_service_role_arn" {
  description = "IAM Role ARN for Kubernetes Service Account (IRSA)"
  value       = aws_iam_role.docket_k8s_service_role.arn
}
