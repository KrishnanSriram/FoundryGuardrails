# ===========================================================================
# Guardrails
#
#  Requirement                  Control
#  ---------------------------  ------------------------------------------------
#  PCI (card data, CVV)         Regex blocklist on prompt + completion (below)
#                               + "Credit card Protection" etc. on completion
#                               + app-layer Language PII redaction on input
#  PII                          Per-category "<type> Protection" filters on
#                               completion (preview) + SSN regex blocklist
#                               + app-layer redaction on input
#  Direct prompt hijack         Prompt Shields "Jailbreak" filter (blocking)
#  Indirect prompt hijack       Prompt Shields "Indirect Attack" filter (blocking)
#                               -> app must wrap grounding docs, see app/
#  Baseline safety              Hate/Sexual/Violence/Selfharm at Low threshold,
#                               protected material text/code
# ===========================================================================

# ---- PCI / PII regex blocklist -------------------------------------------
resource "azapi_resource" "pci_blocklist" {
  type      = "Microsoft.CognitiveServices/accounts/raiBlocklists@2025-06-01"
  name      = "pci-pii-patterns"
  parent_id = azapi_resource.foundry.id

  body = {
    properties = {
      description = "Card numbers (Visa/MC/Amex/Discover), CVV, US SSN"
    }
  }
}

# Blocklist items go through the blocklist's batch endpoints rather than
# per-item URLs. The per-item endpoint answers azapi's pre-flight GET with a
# bare 400 (instead of 404/200), which fails both azapi_resource and
# azapi_resource_action. The batch actions are POSTs on the blocklist itself,
# so the pre-flight GET hits the blocklist, which responds normally.
locals {
  # Item names: lowercase, hyphens only.
  pci_items = {
    for k, v in var.pci_regex_patterns : replace(k, "_", "-") => v
  }
}

# Upserts every pattern in one call. Re-runs whenever a pattern is added or
# changed; existing items with the same name are overwritten.
resource "azapi_resource_action" "pci_blocklist_items" {
  type        = "Microsoft.CognitiveServices/accounts/raiBlocklists@2025-06-01"
  resource_id = azapi_resource.pci_blocklist.id
  action      = "addRaiBlocklistItems"
  method      = "POST"

  body = [
    for name, pattern in local.pci_items : {
      name       = name
      properties = { pattern = pattern, isRegex = true }
    }
  ]
}

# One destroy-time delete per item, so removing a pattern from tfvars also
# removes it from Azure (and terraform destroy cleans up).
resource "azapi_resource_action" "pci_blocklist_item_delete" {
  for_each    = local.pci_items
  type        = "Microsoft.CognitiveServices/accounts/raiBlocklists@2025-06-01"
  resource_id = azapi_resource.pci_blocklist.id
  action      = "deleteRaiBlocklistItems"
  method      = "POST"
  when        = "destroy"
  body        = [each.key]
}

# ---- Content filter policy (a.k.a. guardrail / RAI policy) ----------------
locals {
  harm_categories = ["Hate", "Sexual", "Violence", "Selfharm"]

  harm_filters = flatten([
    for c in local.harm_categories : [
      for src in ["Prompt", "Completion"] : {
        name              = c
        source            = src
        enabled           = true
        blocking          = true
        severityThreshold = var.harm_severity_threshold
      }
    ]
  ])

  shield_filters = [
    # Direct prompt injection / jailbreak in the user turn
    { name = "Jailbreak", source = "Prompt", enabled = true, blocking = true },
    # Indirect / cross-domain injection hidden in documents, emails, tool output
    { name = "Indirect Attack", source = "Prompt", enabled = true, blocking = true },
    { name = "Protected Material Text", source = "Completion", enabled = true, blocking = true },
    { name = "Protected Material Code", source = "Completion", enabled = true, blocking = true },
  ]

  pii_filters = var.enable_pii_output_filter ? [
    for c in var.pii_output_categories :
    { name = c, source = "Completion", enabled = true, blocking = true }
  ] : []
}

resource "azapi_resource" "guardrail_policy" {
  type      = "Microsoft.CognitiveServices/accounts/raiPolicies@2025-07-01-preview"
  name      = "strict-pii-pci-shields"
  parent_id = azapi_resource.foundry.id

  # Filter names are validated server-side; skip local schema checks so new
  # filters (e.g. PII) aren't rejected by an older embedded schema.
  schema_validation_enabled = false

  body = {
    properties = {
      basePolicyName = "Microsoft.DefaultV2"
      mode           = "Blocking"
      contentFilters = concat(local.harm_filters, local.shield_filters, local.pii_filters)
      customBlocklists = [
        { blocklistName = azapi_resource.pci_blocklist.name, source = "Prompt", blocking = true },
        { blocklistName = azapi_resource.pci_blocklist.name, source = "Completion", blocking = true },
      ]
    }
  }

  depends_on = [azapi_resource_action.pci_blocklist_items]
}
