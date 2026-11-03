"""
Diagnose why the PII output filters didn't block.

Sends the same PII-producing request through:
  1. the /openai/v1/ endpoint (what guarded_chat.py uses; no api-version)
  2. the classic deployments endpoint with api-version 2025-04-01-preview
     (PII filtering is documented as needing 2025-01-01-preview or later)
and prints finish_reason plus the full completion-side filter verdicts, so
you can see whether any PII entries appear at all.

  uv run --env-file .env app/probe_pii.py
"""
import json
import os

import openai
from azure.identity import DefaultAzureCredential, get_bearer_token_provider

token = get_bearer_token_provider(
    DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default"
)
DEPLOYMENT = os.environ["DEPLOYMENT"]
V1 = os.environ["AZURE_OPENAI_ENDPOINT"]                 # .../openai/v1/
BASE = V1.split("/openai/")[0]                           # https://<acct>.openai.azure.com

PROMPT = ("Write a sample support signature for Jane at Contoso, including "
          "email jane.doe@contoso.com and phone (425) 555-0142.")

CLIENTS = {
    "v1 endpoint (no api-version)":
        openai.OpenAI(base_url=V1, api_key=token),
    "deployments endpoint, api-version 2025-04-01-preview":
        openai.AzureOpenAI(azure_endpoint=BASE, azure_ad_token_provider=token,
                           api_version="2025-04-01-preview"),
    "deployments endpoint, api-version 2026-03-17":
        openai.AzureOpenAI(azure_endpoint=BASE, azure_ad_token_provider=token,
                            api_version="2026-03-17")
}

for label, client in CLIENTS.items():
    print(f"=== {label}")
    try:
        r = client.chat.completions.create(
            model=DEPLOYMENT,
            messages=[{"role": "user", "content": PROMPT}],
            max_completion_tokens=200,
        )
    except openai.BadRequestError as e:
        print(f"  BLOCKED on input: {json.dumps(e.body, indent=2)}")
        continue

    ch = r.choices[0]
    cfr = (ch.model_extra or {}).get("content_filter_results", {})
    print(f"  finish_reason: {ch.finish_reason}")
    print(f"  filter keys present: {sorted(cfr)}")
    print("  completion filter results:")
    print("    " + json.dumps(cfr, indent=2).replace("\n", "\n    "))
    print(f"  text: {ch.message.content!r}\n")