variable "environment" {
  type        = string
  description = "Target deployment environment (e.g., dev, staging, prod)"
  default     = "prod"
}

variable "location" {
  type        = string
  description = "Azure region for all G1 Docket resources"
  default     = "eastus"
}

variable "resource_group_name" {
  type        = string
  description = "Name of the existing or target Azure Resource Group"
  default     = "rg-g1-docket-prod"
}

variable "storage_account_name" {
  type        = string
  description = "Globally unique name of the Azure Storage Account (3-24 alphanumeric characters, lowercase)"
  default     = "stg1docketprodworm"
}

variable "retention_days" {
  type        = number
  description = "Immutability retention period in days (2555 days = 7 years for SEC Rule 17a-4 / FINRA compliance)"
  default     = 2555
}

variable "immutability_policy_state" {
  type        = string
  description = "Immutability state: 'Locked' for non-revertible statutory WORM, or 'Unlocked' for testing"
  default     = "Locked"
}

variable "aks_oidc_issuer_url" {
  type        = string
  description = "OIDC Issuer URL of the AKS cluster for Workload Identity federation"
  default     = "https://eastus.oic.prod-aks.azure.com/00000000-0000-0000-0000-000000000000/"
}

variable "k8s_namespace" {
  type        = string
  description = "Kubernetes namespace running G1 Docket pods"
  default     = "g1-docket-system"
}

variable "k8s_service_account" {
  type        = string
  description = "Kubernetes ServiceAccount name for G1 Docket pods"
  default     = "g1-docket-sa"
}
