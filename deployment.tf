# Nano GPT deployment with the guardrail policy attached.
resource "azapi_resource" "gpt_nano" {
  type      = "Microsoft.CognitiveServices/accounts/deployments@2025-06-01"
  name      = var.model_name
  parent_id = azapi_resource.foundry.id

  body = {
    sku = {
      name     = var.deployment_sku
      capacity = var.deployment_capacity
    }
    properties = {
      model = {
        format  = "OpenAI"
        name    = var.model_name
        version = var.model_version
      }
      raiPolicyName        = azapi_resource.guardrail_policy.name
      versionUpgradeOption = "OnceNewDefaultVersionAvailable"
    }
  }

  # Account-level operations can't run concurrently; serialize after the project.
  depends_on = [azapi_resource.project]
}
