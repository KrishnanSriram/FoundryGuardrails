# Azure AI Foundry + guardrails (Terraform)

A Foundry resource and project, one **nano GPT** deployment (cheapest tier), and a
guardrail (RAI policy) attached to it covering PII, PCI and direct/indirect prompt
injection.

## What gets created

| File                                        | Resources                                                                                         |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `main.tf`                                   | Resource group, Foundry account (`AIServices`, keyless/Entra-only), Foundry project, RBAC for you |
| `guardrails.tf`                             | PCI/PII regex blocklist + RAI policy (the guardrail)                                              |
| `deployment.tf`                             | `gpt-5.4-nano` GlobalStandard deployment with the guardrail attached                              |
| `app/guarded_chat.py`                       | Client showing the app-side pieces + a 6-case smoke test                                          |
| `app/probe_indirect.py`, `app/probe_pii.py` | Diagnostics for the indirect-attack shield and PII output filters                                 |
| `scripts/list-content-filters.sh`           | Lists the content filter names Azure accepts in a region                                          |

## Guardrail coverage

| Requirement                              | Server-side (Terraform)                                                                                                    | App-side (`app/`)                                                                        |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| **PCI**: card numbers, CVV, bank details | Regex blocklist on prompt **and** completion; Credit card / EU debit / bank / ABA / IBAN / SWIFT output filters            | Language PII redaction on input                                                          |
| **PII**                                  | Per-category `<type> Protection` output filters (SSN, ITIN, licence, passport, email, phone, address, secrets) + SSN regex | Language PII redaction on input                                                          |
| **Direct prompt hijack**                 | Prompt Shields `Jailbreak`, blocking                                                                                       | n/a                                                                                      |
| **Indirect prompt hijack**               | Prompt Shields `Indirect Attack`, blocking                                                                                 | **Must** put untrusted content in the user message as `""" <documents>…</documents> """` |
| Baseline                                 | Hate/Sexual/Violence/Self-harm at **Low**, protected material text/code                                                    | n/a                                                                                      |

Why both layers for PII/PCI: Foundry's PII filters only screen **output**. The regex
blocklist rejects card data in prompts, but redacting before the call is what keeps
data from ever reaching the model.

## Prerequisites

- Terraform >= 1.9
- Azure CLI (`az`), signed in with `az login`
- [uv](https://docs.astral.sh/uv/)
- `jq` (only to generate `.env`)

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

## Deploy

```bash
az login
cp terraform.tfvars.example terraform.tfvars   # set subscription_id
./scripts/list-content-filters.sh eastus2      # optional: confirm filter names + nano availability
terraform init
terraform apply
```

Role assignments can take a few minutes to propagate. If you get 401/403, wait and retry.
Guardrail policy changes can also take a few minutes before they're enforced.

## Python setup (uv)

Python 3.13 (pinned in `.python-version`). Dependencies are declared in
`pyproject.toml` and locked in `uv.lock`.

| Package                  | Used for                                                                                |
| ------------------------ | --------------------------------------------------------------------------------------- |
| `openai`                 | Calling the gpt-5.4-nano deployment via the Foundry `/openai/v1/` endpoint              |
| `azure-identity`         | Entra ID sign-in (`DefaultAzureCredential`); the Foundry resource has API keys disabled |
| `azure-ai-textanalytics` | Language PII redaction on input (`recognize_pii_entities`)                              |

Added with:

```bash
uv add openai azure-identity azure-ai-textanalytics
```

After cloning, install everything from the lock file:

```bash
uv sync
```

## Running the tests

From the repo root:

```bash
uv run --env-file .env app/guarded_chat.py
```

Or from `app/` (`.env` is one level up; `uv` finds `pyproject.toml` in the parent folder):

```bash
cd app
uv run --env-file ../.env guarded_chat.py
uv run --env-file ../.env probe_indirect.py
uv run --env-file ../.env probe_pii.py
```

### `guarded_chat.py`: end-to-end smoke test

```text
--- benign
I can help, but I don't have your company's specific policy in this chat.
If you tell me the store/app/website name (or paste the refund-policy text), I'll summarize it for you.
...

--- pci in prompt (app redaction + blocklist)
  (redacted from question: CreditCardNumber)
[blocked on input by guardrail: blocklist:pci-pii-patterns]

--- pci in prompt (server-side blocklist only)
[blocked on input by guardrail: blocklist:pci-pii-patterns]

--- direct jailbreak
[blocked on input by guardrail: jailbreak]

--- indirect attack
[blocked on input by guardrail: indirect_attack]

--- pii in output (output filters only)
[blocked on output by guardrail: pii:Email/PhoneNumber]
```

| Test                            | Control proven                                                                  |
| ------------------------------- | ------------------------------------------------------------------------------- |
| benign                          | Normal requests pass through                                                    |
| pci (app redaction + blocklist) | Language API redacts the card number; the regex blocklist still catches the CVV |
| pci (server-side only)          | Blocklist blocks card data even without app-side redaction                      |
| direct jailbreak                | Prompt Shields jailbreak filter                                                 |
| indirect attack                 | Prompt Shields indirect-attack filter on a document in the user message         |
| pii in output                   | PII output filters (email, phone) block the reply                               |

### `probe_indirect.py`: where documents must go

```text
--- subtle injection | doc in USER message
  outcome: BLOCKED
  shields: {"indirect_attack": {"detected": true, "filtered": true}, "jailbreak": {"detected": false, "filtered": false}}

--- subtle injection | doc in SYSTEM message
  outcome: ALLOWED
  prompt_index 0: {"indirect_attack": {"detected": false, "filtered": false}, "jailbreak": {"detected": false, "filtered": false}}

--- harmless control | doc in USER message
  outcome: ALLOWED
  ...

--- harmless control | doc in SYSTEM message
  outcome: ALLOWED
  ...
```

**Takeaway:** the indirect-attack shield only scans documents in the **user** message,
wrapped as `""" <documents>...</documents> """`. The same injection in the system message gets through.

### `probe_pii.py`: PII output filter verdicts

```text
=== v1 endpoint (no api-version)
  finish_reason: content_filter
  filter keys present: ['custom_blocklists', 'personally_identifiable_information', 'protected_material_code', 'protected_material_text']
  completion filter results:
    "personally_identifiable_information": {
      "filtered": true, "detected": true,
      "sub_categories": [
        {"sub_category": "Email",       "filtered": true, "detected": true, "redacted": true},
        {"sub_category": "PhoneNumber", "filtered": true, "detected": true, "redacted": true},
        ... (14 other categories: not detected)
      ]
    }
  text: 'Jane Doe  \nSupport Specialist, Contoso  \nEmail: jane.doe@contoso.com  \nPhone: (425) 555-0142'

=== deployments endpoint, api-version 2025-04-01-preview
  (same verdict)
```

**Takeaway:** the filter flags the reply (`finish_reason: content_filter`), but Azure
**still returns the original text** in `message.content`. Apps must check
`finish_reason` and discard the content; `guarded_chat.py` does this.

## Rules for apps built on this deployment

1. Put grounding documents (RAG chunks, emails, tool output) in the **user** message,
   wrapped as `""" <documents>…</documents> """` with JSON-escaped content.
2. Check `finish_reason` before using `message.content`; discard it on `content_filter`.
3. Redact PII on input before calling the model.

## Versions

| Version                    | Value                                                 | Notes                                                                                                                        |
| -------------------------- | ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Model version              | `2026-03-17`                                          | What the portal shows. `versionUpgradeOption = "OnceNewDefaultVersionAvailable"` auto-upgrades; use `"NoAutoUpgrade"` to pin |
| Management API (Terraform) | `2025-06-01`; `2025-07-01-preview` for the RAI policy | The preview is needed for the newer filters                                                                                  |
| Inference API              | none                                                  | The `/openai/v1/` endpoint is unversioned                                                                                    |

## Things to check / adjust

- **PII output filters.** Azure exposes PII as one filter per type ("Credit card Protection",
  "Email Protection", ...). Tune the list in `pii_output_categories`; exact names come from
  `scripts/list-content-filters.sh`. If apply fails with _"content filter … is not supported"_,
  a name doesn't match your region exactly. `Name Protection` is left off on purpose: it
  blocks any reply containing a person's name.
- **Model availability.** If `gpt-5.4-nano` isn't offered in your region, switch to
  `gpt-4.1-nano` / `2025-04-14` in tfvars.
- **Regex blocklist** matches are simple patterns with no Luhn check, so expect some false
  positives on long digit strings (order IDs etc.). Tune `pci_regex_patterns`.
- **Blocklist items** are managed through the blocklist's batch endpoints
  (`addRaiBlocklistItems` / `deleteRaiBlocklistItems`). The per-item endpoint returns a
  bare 400 to azapi's pre-flight GET, which breaks `azapi_resource`.
- **Changing the policy name** later: the deployment references it, so Azure refuses
  to delete the old one while in use. Rename in two applies or detach first.
- **Other models (e.g. Claude).** Foundry guardrails only apply to models sold by Azure.
  Claude deployments need these checks done in the app or a gateway with the Content
  Safety APIs (Prompt Shields, text analysis) plus Language PII on input and output.
- **PCI DSS scope.** These controls reduce the chance of card data reaching the
  model; they don't by themselves make the workload PCI compliant. For production,
  add a private endpoint (`publicNetworkAccess = "Disabled"`), diagnostic logs, and
  keep cardholder data out of logs and prompts upstream.

## Tear down

```bash
terraform destroy
# Foundry accounts are soft-deleted for 48h; purge to free the name/quota:
az cognitiveservices account purge --name <account> --resource-group <rg> --location eastus2
```

If you delete the resource group in the portal instead, also delete the local
`terraform.tfstate*` files before the next `terraform apply`.
