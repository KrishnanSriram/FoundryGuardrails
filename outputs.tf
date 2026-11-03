output "resource_group" {
  value = azurerm_resource_group.this.name
}

output "foundry_account_name" {
  value = azapi_resource.foundry.name
}

output "openai_v1_endpoint" {
  description = "Base URL for the OpenAI SDK (Entra ID auth)."
  value       = "https://${azapi_resource.foundry.name}.openai.azure.com/openai/v1/"
}

output "cognitive_endpoint" {
  description = "Used for the Language PII redaction call."
  value       = "https://${azapi_resource.foundry.name}.cognitiveservices.azure.com"
}

output "project_endpoint" {
  value = "https://${azapi_resource.foundry.name}.services.ai.azure.com/api/projects/${azapi_resource.project.name}"
}

output "deployment_name" {
  value = azapi_resource.gpt_nano.name
}

output "guardrail_policy_id" {
  description = "Full ARM ID - also usable as rai_policy_name on Foundry hosted agents."
  value       = azapi_resource.guardrail_policy.id
}
