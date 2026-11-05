# ===========================================================================
# Guardrails: built-in (out-of-the-box) controls only, no custom regex.
#
#  Requirement                  Control
#  ---------------------------  ------------------------------------------------
#  PCI (card / bank data)       "Credit card Protection", "EU debit card...",
#                               bank / ABA / IBAN / SWIFT filters on completion
#                               + app-layer Language PII redaction on input
#  PII                          Per-category "<type> Protection" filters on
#                               completion (preview) + app-layer redaction on input
#  Direct prompt hijack         Prompt Shields "Jailbreak" filter (blocking)
#  Indirect prompt hijack       Prompt Shields "Indirect Attack" filter (blocking)
#                               -> app must wrap grounding docs, see app/
#  Baseline safety              Hate/Sexual/Violence/Selfharm at Low threshold,
#                               protected material text/code
#
# Foundry's PII filters only screen model OUTPUT. Input-side PII/PCI protection
# is the app's job (Azure AI Language redaction in app/), which is also built-in.
# ===========================================================================

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
      basePolicyName   = "Microsoft.DefaultV2"
      mode             = "Blocking"
      contentFilters   = concat(local.harm_filters, local.shield_filters, local.pii_filters)
      customBlocklists = [] # no custom regex; explicit so earlier blocklists are detached
    }
  }
}
