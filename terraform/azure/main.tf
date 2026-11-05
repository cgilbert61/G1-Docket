terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }
  }
}

data "azurerm_client_config" "current" {}

# 1. Resource Group
resource "azurerm_resource_group" "docket_rg" {
  name     = var.resource_group_name
  location = var.location

  tags = {
    Environment = var.environment
    Application = "G1-Docket"
    Compliance  = "SEC-17a-4-WORM"
  }
}

# 2. Azure Key Vault for Envelope Encryption & Cryptographic Key Management
resource "azurerm_key_vault" "docket_kv" {
  name                        = "kv-g1-docket-${var.environment}"
  location                    = azurerm_resource_group.docket_rg.location
  resource_group_name         = azurerm_resource_group.docket_rg.name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "premium" # HSM-backed key protection
  soft_delete_retention_days  = 90
  purge_protection_enabled    = true      # Prevents permanent deletion before retention period expires
  enable_rbac_authorization   = true

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }

  tags = {
    Environment = var.environment
    Application = "G1-Docket"
    Purpose     = "Attestation-Envelope-CMK"
  }
}

# RSA 4096 Key for WORM Ledger & Attestation DSSE Envelope Encryption
resource "azurerm_key_vault_key" "docket_cmk" {
  name         = "key-g1-docket-cmk-${var.environment}"
  key_vault_id = azurerm_key_vault.docket_kv.id
  key_type     = "RSA-HSM"
  key_size     = 4096

  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "verify",
    "wrapKey",
    "unwrapKey"
  ]

  tags = {
    Environment = var.environment
    Application = "G1-Docket"
  }
}

# 3. Storage Account with Infrastructure Encryption & TLS 1.2
resource "azurerm_storage_account" "docket_storage" {
  name                          = var.storage_account_name
  resource_group_name           = azurerm_resource_group.docket_rg.name
  location                      = azurerm_resource_group.docket_rg.location
  account_tier                  = "Standard"
  account_replication_type       = "ZRS" # Zone-Redundant Storage for multi-AZ resilience
  account_kind                  = "StorageV2"
  min_tls_version               = "TLS1_2"
  infrastructure_encryption_enabled = true
  allow_nested_items_to_be_public = false

  blob_properties {
    versioning_enabled       = true
    change_feed_enabled      = true
    last_access_time_enabled = true

    container_delete_retention_policy {
      days = 30
    }
  }

  identity {
    type = "UserAssigned"
    identity_ids = [
      azurerm_user_assigned_identity.docket_workload_id.id
    ]
  }

  tags = {
    Environment = var.environment
    Application = "G1-Docket"
    Compliance  = "SEC-17a-4-WORM"
    Regulatory  = "EU-AI-Act-Art10"
  }
}

# 4. Storage Container for WORM Ledger
resource "azurerm_storage_container" "worm_ledger_container" {
  name                  = "g1-docket-worm-ledger"
  storage_account_name  = azurerm_storage_account.docket_storage.name
  container_access_type = "private"
}

# Time-Based Immutability Policy (SEC Rule 17a-4 / FINRA Rule 4511)
resource "azurerm_storage_container_immutability_policy" "worm_policy" {
  storage_container_resource_manager_id = azurerm_storage_container.worm_ledger_container.resource_manager_id
  immutability_period_in_days           = var.retention_days
  protected_append_blobs_enabled        = true # Allows incremental line appending for JSONL WORM ledger
  state                                 = var.immutability_policy_state
}

# 5. User-Assigned Managed Identity for AKS Workload Identity
resource "azurerm_user_assigned_identity" "docket_workload_id" {
  name                = "id-g1-docket-${var.environment}"
  resource_group_name = azurerm_resource_group.docket_rg.name
  location            = azurerm_resource_group.docket_rg.location

  tags = {
    Environment = var.environment
    Application = "G1-Docket"
  }
}

# Federated Identity Credential for AKS ServiceAccount
resource "azurerm_federated_identity_credential" "docket_federation" {
  name                = "fed-g1-docket-${var.environment}"
  resource_group_name = azurerm_resource_group.docket_rg.name
  audience            = ["api://AzureADTokenExchange"]
  issuer              = var.aks_oidc_issuer_url
  parent_id           = azurerm_user_assigned_identity.docket_workload_id.id
  subject             = "system:serviceaccount:${var.k8s_namespace}:${var.k8s_service_account}"
}

# RBAC: Storage Blob Data Contributor on WORM Storage Account
resource "azurerm_role_assignment" "storage_data_contributor" {
  scope                = azurerm_storage_account.docket_storage.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.docket_workload_id.principal_id
}

# RBAC: Key Vault Crypto User for CMK Operations
resource "azurerm_role_assignment" "kv_crypto_user" {
  scope                = azurerm_key_vault.docket_kv.id
  role_definition_name = "Key Vault Crypto User"
  principal_id         = azurerm_user_assigned_identity.docket_workload_id.principal_id
}
