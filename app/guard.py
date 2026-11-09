"""
Guardrails for any model, using only built-in Azure services (no custom regex).
The same checks run for GPT and Claude.

  Before the model (screen_input)          After the model (screen_output)
  -------------------------------          -------------------------------
  Language: redact PII / PCI               Content Safety: harm categories
  Content Safety: Prompt Shields           Language: block PII / PCI in the reply
    (jailbreak + indirect attack in docs)
  Content Safety: harm categories

Uses Entra ID (the Foundry account has API keys disabled) and the same
Foundry resource. Needs the "Cognitive Services User" role.

Errors fail closed: if a check can't run, it raises and the model isn't called.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import requests
from azure.ai.textanalytics import TextAnalyticsClient
from azure.identity import get_bearer_token_provider

CONTENT_SAFETY_API = "2024-09-01"

# Content Safety severities: 0 safe, 2 low, 4 medium, 6 high.
# Same meaning as harm_severity_threshold in variables.tf.
SEVERITY_FLOOR = {"Low": 2, "Medium": 4, "High": 6}

# PII / PCI that blocks a reply. Matches pii_output_categories in variables.tf.
BLOCK_CATEGORIES = {
    "CreditCardNumber", "EUDebitCardNumber", "USBankAccountNumber",
    "ABARoutingNumber", "InternationalBankingAccountNumber", "SWIFTCode",
    "USSocialSecurityNumber", "USIndividualTaxpayerIdentification",
    "USDriversLicenseNumber", "USUKPassportNumber",
    "Email", "PhoneNumber", "Address",
    "AzureStorageAccountKey", "AzureSAS", "SQLServerConnectionString",
}

# PII / PCI masked in the request: everything above, plus names and IPs.
REDACT_CATEGORIES = sorted(BLOCK_CATEGORIES | {"Person", "IPAddress"})


@dataclass
class Verdict:
    allowed: bool
    reasons: list[str] = field(default_factory=list)   # why it was blocked
    redacted: list[str] = field(default_factory=list)  # PII categories masked in the request
    text: str = ""                                     # question to send (redacted)
    docs: list[str] = field(default_factory=list)      # documents to send (redacted)


class Guard:
    def __init__(self, cognitive_endpoint: str, credential, harm_threshold: str = "Low"):
        self.endpoint = cognitive_endpoint.rstrip("/")
        self._token = get_bearer_token_provider(
            credential, "https://cognitiveservices.azure.com/.default")
        self._language = TextAnalyticsClient(self.endpoint, credential)
        self.severity_floor = SEVERITY_FLOOR[harm_threshold]
        self._pool = ThreadPoolExecutor(max_workers=4)

    # ------------------------------------------------------------- the two checks
    def screen_input(self, question: str, docs: list[str] | None = None) -> Verdict:
        """Mask PII, then run Prompt Shields and the harm check in parallel."""
        question, found = self.redact(question)
        redacted = set(found)
        clean_docs = []
        for d in docs or []:
            d, found = self.redact(d)
            redacted |= set(found)
            clean_docs.append(d)

        shields = self._pool.submit(self.prompt_shields, question, clean_docs)
        harm = self._pool.submit(self.harm, "\n".join([question, *clean_docs]))
        reasons = shields.result() + harm.result()
        return Verdict(not reasons, reasons, sorted(redacted), question, clean_docs)

    def screen_output(self, text: str) -> Verdict:
        """Harm check and PII / PCI detection on a model reply, in parallel."""
        harm = self._pool.submit(self.harm, text)
        pii = self._pool.submit(self.detect_pii, text)
        reasons = harm.result() + ([f"pii:{'/'.join(pii.result())}"] if pii.result() else [])
        return Verdict(not reasons, reasons, text=text)

    # ------------------------------------------------------- individual services
    def redact(self, text: str) -> tuple[str, list[str]]:
        """Language PII: returns (text with PII masked as ***, categories found)."""
        r = self._pii(text, REDACT_CATEGORIES)
        return r.redacted_text, sorted({e.category for e in r.entities})

    def detect_pii(self, text: str) -> list[str]:
        """Language PII: blocking categories present in text."""
        if not text.strip():
            return []
        return sorted({e.category for e in self._pii(text).entities} & BLOCK_CATEGORIES)

    def prompt_shields(self, user_prompt: str, docs: list[str]) -> list[str]:
        """Content Safety Prompt Shields: jailbreak in the prompt, attacks in documents."""
        res = self._content_safety("shieldPrompt", {"userPrompt": user_prompt, "documents": docs})
        reasons = ["jailbreak"] if res.get("userPromptAnalysis", {}).get("attackDetected") else []
        reasons += [f"indirect_attack(doc {i})"
                    for i, d in enumerate(res.get("documentsAnalysis", [])) if d.get("attackDetected")]
        return reasons

    def harm(self, text: str) -> list[str]:
        """Content Safety text analysis: hate, sexual, violence, self-harm."""
        if not text.strip():
            return []
        res = self._content_safety("analyze", {"text": text, "outputType": "FourSeverityLevels"})
        return [f"{c['category'].lower()}(severity {c['severity']})"
                for c in res.get("categoriesAnalysis", [])
                if c.get("severity", 0) >= self.severity_floor]

    # ------------------------------------------------------------------ plumbing
    def _pii(self, text: str, categories: list[str] | None = None):
        kwargs = {"language": "en"}
        if categories:
            kwargs["categories_filter"] = categories
        result = self._language.recognize_pii_entities([text], **kwargs)[0]
        if result.is_error:
            raise RuntimeError(f"PII check failed: {result.error}")
        return result

    def _content_safety(self, operation: str, body: dict) -> dict:
        r = requests.post(
            f"{self.endpoint}/contentsafety/text:{operation}",
            params={"api-version": CONTENT_SAFETY_API},
            headers={"Authorization": f"Bearer {self._token()}"},
            json=body, timeout=15,
        )
        if r.status_code != 200:
            raise RuntimeError(f"Content Safety {operation} failed: {r.status_code} {r.text}")
        return r.json()
