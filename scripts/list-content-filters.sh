#!/usr/bin/env bash
# Lists the content-filter names Azure accepts in a region, so you can confirm
# the exact PII / Jailbreak / Indirect Attack names before `terraform apply`.
# Usage: ./scripts/list-content-filters.sh eastus2
set -euo pipefail
LOCATION="${1:-eastus2}"
SUB="$(az account show --query id -o tsv)"

az rest --method get \
  --url "https://management.azure.com/subscriptions/${SUB}/providers/Microsoft.CognitiveServices/locations/${LOCATION}/raiContentFilters?api-version=2025-06-01" \
  --query "value[].{name:properties.name, source:properties.source, multiLevel:properties.isMultiLevelFilter}" \
  -o table

echo
echo "Model availability (nano models) in ${LOCATION}:"
az cognitiveservices model list --location "${LOCATION}" \
  --query "[?contains(model.name,'nano')].{name:model.name, version:model.version, skus:join(',', model.skus[].name)}" \
  -o table
