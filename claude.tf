# ===========================================================================
# Claude (Anthropic) deployment on the same Foundry account.
#
# Foundry guardrails (the RAI policy in guardrails.tf) do NOT apply to Claude:
# Microsoft's docs say Foundry "doesn't provide built-in content filtering for
# Claude models". The same checks are applied in code instead: app/guard.py
# (Content Safety Prompt Shields + harm analysis, Language PII). No custom regex.
#
# Requirements:
#   - Paid subscription with a pay-as-you-go payment method (no free trial,
#     credits-only, or CSP subscriptions).
#   - Azure Marketplace access. The modelProviderData block below accepts the
#     Anthropic offer terms on your behalf: review
#     https://www.anthropic.com/legal/commercial-terms before applying.
#
# Pattern taken from Microsoft's Claude-on-Foundry starter kit
# (github.com/Azure-Samples/claude, infra-terraform).
# ===========================================================================

resource "azapi_resource" "claude" {
  count     = var.enable_claude ? 1 : 0
  type      = "Microsoft.CognitiveServices/accounts/deployments@2025-10-01-preview"
  name      = var.claude_model
  parent_id = azapi_resource.foundry.id

  # modelProviderData isn't in the embedded schema
  schema_validation_enabled = false

  body = {
    sku = {
      name     = "GlobalStandard"
      capacity = var.claude_capacity
    }
    properties = {
      model = {
        format  = "Anthropic"
        name    = var.claude_model
        version = var.claude_model_version
      }
      modelProviderData = {
        organizationName = var.claude_organization_name
        countryCode      = var.claude_country_code
        industry         = var.claude_industry
      }
      # Required field; it doesn't add filtering for Claude (see header).
      raiPolicyName        = "Microsoft.DefaultV2"
      versionUpgradeOption = "OnceNewDefaultVersionAvailable"
    }
  }

  lifecycle {
    precondition {
      condition     = length(trimspace(var.claude_organization_name)) > 0
      error_message = "Set claude_organization_name in terraform.tfvars (or set enable_claude = false)."
    }
  }

  # Account-level operations can't run concurrently: deploy after the GPT model.
  depends_on = [azapi_resource.gpt_nano]
}
