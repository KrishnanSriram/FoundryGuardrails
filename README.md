## Configuration files

Neither file is committed (see `.gitignore`). Copy the `.example` versions and fill them in.

### `terraform.tfvars`

```bash
cp terraform.tfvars.example terraform.tfvars
```

```hcl
# Required
subscription_id = "00000000-0000-0000-0000-000000000000"   # az account show --query id -o tsv

# Optional (defaults shown)
prefix   = "aifdemo"   # 3-12 lowercase letters/numbers; a random suffix is added
location = "eastus2"   # eastus2 / swedencentral have the widest model availability

# Model: cheapest GPT tier. Fall back to gpt-4.1-nano / 2025-04-14 if
# gpt-5.4-nano isn't offered in your region.
model_name          = "gpt-5.4-nano"
model_version       = "2026-03-17"
deployment_sku      = "GlobalStandard"   # pay-per-token
deployment_capacity = 10                 # throughput cap in K tokens/min, not a cost

# Guardrails
harm_severity_threshold  = "Low"   # Low (strictest) | Medium | High
enable_pii_output_filter = true

# Optional: override which PII/PCI output filters are on. Names must match
# exactly; list them with ./scripts/list-content-filters.sh <region>
# pii_output_categories = [
#   "Credit card Protection",
#   "U.S. Social Security Number (SSN) Protection",
#   "Email Protection",
#   "Phone Number Protection",
# ]

# Optional: give the identity running Terraform access to call the model
grant_current_user_access = true
```

### `.env`

Generate after `terraform apply`:

```bash
terraform output -json | jq -r '"AZURE_OPENAI_ENDPOINT=\(.openai_v1_endpoint.value)\nAZURE_COGNITIVE_ENDPOINT=\(.cognitive_endpoint.value)\nDEPLOYMENT=\(.deployment_name.value)"' > .env
```

Resulting contents (`<name>` is `<prefix><random suffix>`, e.g. `aifdemoq5hbn`):

```bash
AZURE_OPENAI_ENDPOINT=https://aif-<name>.openai.azure.com/openai/v1/
AZURE_COGNITIVE_ENDPOINT=https://aif-<name>.cognitiveservices.azure.com
DEPLOYMENT=gpt-5.4-nano
```

`.env` has no keys: authentication is Entra ID (`az login`) only.