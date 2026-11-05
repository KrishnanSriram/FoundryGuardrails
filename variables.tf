variable "subscription_id" {
  description = "Azure subscription to deploy into."
  type        = string
}

variable "prefix" {
  description = "Short name prefix for all resources (lowercase letters/numbers)."
  type        = string
  default     = "aifdemo"

  validation {
    condition     = can(regex("^[a-z0-9]{3,12}$", var.prefix))
    error_message = "prefix must be 3-12 lowercase letters/numbers."
  }
}

variable "location" {
  description = "Region. Pick one where your chosen model is offered as GlobalStandard (eastus2 / swedencentral are the safest bets)."
  type        = string
  default     = "eastus2"
}

# ---------------------------------------------------------------------------
# Model - smallest/cheapest GPT tier ("nano"). Swap via tfvars if the model
# isn't available in your region/subscription.
#   gpt-5.4-nano  2026-03-17   (newest nano)
#   gpt-5-nano    2025-08-07
#   gpt-4.1-nano  2025-04-14   (non-reasoning, very cheap, widely available)
# ---------------------------------------------------------------------------
variable "model_name" {
  type    = string
  default = "gpt-5.4-nano"
}

variable "model_version" {
  type    = string
  default = "2026-03-17"
}

variable "deployment_sku" {
  description = "GlobalStandard = pay-per-token, cheapest. DataZoneStandard if you need US/EU data residency."
  type        = string
  default     = "GlobalStandard"
}

variable "deployment_capacity" {
  description = "Rate limit in thousands of tokens/minute (10 = 10K TPM). Pay-per-token, so this caps throughput, not cost."
  type        = number
  default     = 10
}

# ---------------------------------------------------------------------------
# Guardrail tuning
# ---------------------------------------------------------------------------
variable "harm_severity_threshold" {
  description = "Block harm categories at this severity and above: Low (strictest), Medium, High."
  type        = string
  default     = "Low"

  validation {
    condition     = contains(["Low", "Medium", "High"], var.harm_severity_threshold)
    error_message = "Must be Low, Medium or High."
  }
}

variable "enable_pii_output_filter" {
  description = "Enable Azure's built-in PII filters (preview) on model output."
  type        = bool
  default     = true
}

# Azure exposes PII as one filter per data type, named "<type> Protection".
# Names must match exactly (case, spaces, punctuation). Full list for a region:
#   ./scripts/list-content-filters.sh eastus2
variable "pii_output_categories" {
  description = "PII/PCI filter names to block on model output."
  type        = list(string)
  default = [
    # PCI / financial
    "Credit card Protection",
    "EU debit card number Protection",
    "U.S. Bank Account Number Protection",
    "ABA routing number Protection",
    "International Banking Account Number (IBAN) Protection",
    "SWIFT code Protection",
    # Government IDs
    "U.S. Social Security Number (SSN) Protection",
    "U.S. Individual Taxpayer Identification Number (ITIN) Protection",
    "U.S. Driver's License Number Protection",
    "U.S. or U.K. Passport Number Protection",
    # Contact details
    "Email Protection",
    "Phone Number Protection",
    "Address Protection",
    # Secrets that sometimes leak from grounding data
    "Azure Storage Account Key Protection",
    "Azure SAS Protection",
    "SQL Server Connection String Protection",
    # Not on by default: "Name Protection" blocks any answer containing a
    # person's name (very noisy for support bots). Add it if you need it.
  ]
}

# ---------------------------------------------------------------------------
# Claude (Anthropic) - see claude.tf
# ---------------------------------------------------------------------------
variable "enable_claude" {
  description = "Deploy a Claude model alongside GPT. Opt-in: deploying accepts Anthropic's offer terms (see claude.tf)."
  type        = bool
  default     = false
}

variable "claude_model" {
  description = "Claude model id. Haiku is the smallest/cheapest family; claude-haiku-4-5 is the older fallback."
  type        = string
  default     = "claude-haiku-5-5"
}

variable "claude_model_version" {
  description = "Claude model version in Foundry (\"1\" for current models)."
  type        = string
  default     = "1"
}

variable "claude_capacity" {
  description = "Rate limit in thousands of tokens/minute. Pay-per-token, so this caps throughput, not cost."
  type        = number
  default     = 25
}

variable "claude_organization_name" {
  description = "Your organization name, sent to Anthropic via modelProviderData (required when enable_claude = true)."
  type        = string
  default     = ""
}

variable "claude_country_code" {
  description = "Two-letter ISO country code for modelProviderData."
  type        = string
  default     = "US"

  validation {
    condition     = length(var.claude_country_code) == 2
    error_message = "Must be a 2-letter country code."
  }
}

variable "claude_industry" {
  description = "Industry for modelProviderData (lowercase)."
  type        = string
  default     = "technology"

  validation {
    condition = contains([
      "technology", "finance", "healthcare", "education",
      "retail", "manufacturing", "government", "media", "other",
    ], var.claude_industry)
    error_message = "Must be one of: technology, finance, healthcare, education, retail, manufacturing, government, media, other."
  }
}

variable "grant_current_user_access" {
  description = "Give the identity running Terraform the 'Cognitive Services OpenAI User' + 'Cognitive Services User' roles so you can test with Entra ID."
  type        = bool
  default     = true
}

variable "tags" {
  type    = map(string)
  default = { workload = "ai-foundry-guardrails" }
}
