data "azurerm_client_config" "current" {}

resource "random_string" "suffix" {
  length  = 5
  upper   = false
  special = false
}

locals {
  name = "${var.prefix}${random_string.suffix.result}"
}

resource "azurerm_resource_group" "this" {
  name     = "rg-${local.name}"
  location = var.location
  tags     = var.tags
}

# ---------------------------------------------------------------------------
# Foundry resource (Microsoft.CognitiveServices/accounts, kind AIServices).
# Hosts the model deployment, guardrails, and the Language PII API.
# ---------------------------------------------------------------------------
resource "azapi_resource" "foundry" {
  type      = "Microsoft.CognitiveServices/accounts@2025-06-01"
  name      = "aif-${local.name}"
  parent_id = azurerm_resource_group.this.id
  location  = var.location
  tags      = var.tags

  identity {
    type = "SystemAssigned"
  }

  body = {
    kind = "AIServices"
    sku  = { name = "S0" }
    properties = {
      customSubDomainName    = "aif-${local.name}"
      allowProjectManagement = true
      disableLocalAuth       = true      # Entra ID only - no API keys to leak
      publicNetworkAccess    = "Enabled" # switch to Disabled + private endpoint for prod
    }
  }

  response_export_values = ["properties.endpoint", "properties.endpoints"]
}

# Foundry project (where apps/agents live; inherits the account's deployments).
resource "azapi_resource" "project" {
  type      = "Microsoft.CognitiveServices/accounts/projects@2025-06-01"
  name      = "proj-${local.name}"
  parent_id = azapi_resource.foundry.id
  location  = var.location

  identity {
    type = "SystemAssigned"
  }

  body = {
    properties = {
      displayName = "Guardrailed project"
      description = "Nano GPT deployment behind PII/PCI + prompt-shield guardrails"
    }
  }
}

# ---------------------------------------------------------------------------
# Optional: let the deploying identity call the model + Language PII API.
# ---------------------------------------------------------------------------
resource "azurerm_role_assignment" "openai_user" {
  count                = var.grant_current_user_access ? 1 : 0
  scope                = azapi_resource.foundry.id
  role_definition_name = "Cognitive Services OpenAI User"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "cog_user" {
  count                = var.grant_current_user_access ? 1 : 0
  scope                = azapi_resource.foundry.id
  role_definition_name = "Cognitive Services User"
  principal_id         = data.azurerm_client_config.current.object_id
}
