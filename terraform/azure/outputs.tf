output "resource_group_name" {
  description = "Azure Resource Group containing G1 Docket resources"
  value       = azurerm_resource_group.docket_rg.name
}

output "key_vault_uri" {
  description = "Vault URI of the Azure Key Vault hosting the CMK"
  value       = azurerm_key_vault.docket_kv.vault_uri
}

output "cmk_key_id" {
  description = "Resource ID of the RSA-4096 CMK used for DSSE envelope and ledger encryption"
  value       = azurerm_key_vault_key.docket_cmk.id
}

output "storage_account_name" {
  description = "Name of the Azure Storage Account hosting the immutable WORM container"
  value       = azurerm_storage_account.docket_storage.name
}

output "worm_container_name" {
  description = "Name of the immutable blob container for the WORM ledger"
  value       = azurerm_storage_container.worm_ledger_container.name
}

output "workload_identity_client_id" {
  description = "Client ID of the User Assigned Managed Identity for AKS Workload Identity"
  value       = azurerm_user_assigned_identity.docket_workload_id.client_id
}
