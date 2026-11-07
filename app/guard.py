"""
Model-agnostic guardrails, for models that Foundry's RAI policy doesn't cover
(e.g. Claude). Mirrors the GPT guardrail in guardrails.tf using only built-in
Azure services (no custom regex):

  Control                  GPT (inline, guardrails.tf)        Here (direct API calls)
  -----------------------  ---------------------------------  ---------------------------------
  Direct prompt hijack     Jailbreak filter                   Content Safety Prompt Shields
  Indirect prompt hijack   Indirect Attack filter             Prompt Shields (documents array)
  Harm categories          Hate/Sexual/Violence/SelfHarm      Content Safety text:analyze
  PCI / PII on input       Language redaction (app)           Language redaction, or
                                                              Language detect-and-block
  PCI / PII on output      "<type> Protection" filters        Language PII detection

All calls use Entra ID (the Foundry account has API keys disabled) and the
same Foundry resource. Needs the "Cognitive Services User" role.

Usage:
    guard = Guard(os.environ["AZURE_COGNITIVE_ENDPOINT"], DefaultAzureCredential())
    v = guard.screen_input(question, docs)
    if not v.allowed: ...           # v.reasons says why
    reply = call_any_model(v.text, v.docs)
    o = guard.screen_output(reply)
    if not o.allowed: ...           # never show the reply
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import requests
from azure.ai.textanalytics import TextAnalyticsClient
from azure.identity import get_bearer_token_provider

CONTENT_SAFETY_API = "2024-09-01"

# Same thresholds as harm_severity_threshold in variables.tf.
# text:analyze returns severities 0 (safe), 2 (low), 4 (medium), 6 (high).
SEVERITY_FLOOR = {"Low": 2, "Medium": 4, "High": 6}

# Blocking categories (Language names) matching pii_output_categories in
# variables.tf. Used on output, and on input when redaction is turned off.
# Detection runs on all categories; only these block.
BLOCK_CATEGORIES = {
    "CreditCardNumber", "EUDebitCardNumber", "USBankAccountNumber",
    "ABARoutingNumber", "InternationalBankingAccountNumber", "SWIFTCode",
    "USSocialSecurityNumber", "USIndividualTaxpayerIdentification",
    "USDriversLicenseNumber", "USUKPassportNumber",
    "Email", "PhoneNumber", "Address",
    "AzureStorageAccountKey", "AzureSAS", "SQLServerConnectionString",
}

# Input redaction: everything that blocks on output, plus names and IPs
# (redacting those is harmless, blocking on them would be too noisy).
INPUT_REDACT_CATEGORIES = sorted(BLOCK_CATEGORIES | {"Person", "IPAddress"})
OUTPUT_BLOCK_CATEGORIES = BLOCK_CATEGORIES  # backwards-compatible name


@dataclass
class Verdict:
    allowed: bool
    reasons: list[str] = field(default_factory=list)  # why it was blocked
    notes: list[str] = field(default_factory=list)    # e.g. what was redacted
    text: str = ""                                    # (redacted) text to use
    docs: list[str] = field(default_factory=list)     # (redacted) documents


class Guard:
    def __init__(self, cognitive_endpoint: str, credential,
                 harm_threshold: str = "Low",
                 block_categories: set[str] | None = None,
                 timeout: float = 15.0):
        self.endpoint = cognitive_endpoint.rstrip("/")
        self._token = get_bearer_token_provider(
            credential, "https://cognitiveservices.azure.com/.default")
        self._language = TextAnalyticsClient(self.endpoint, credential)
        self.severity_floor = SEVERITY_FLOOR[harm_threshold]
        self.output_block = block_categories or BLOCK_CATEGORIES
        self.timeout = timeout
        self._pool = ThreadPoolExecutor(max_workers=4)

    # ------------------------------------------------------------------ calls
    def _content_safety(self, operation: str, body: dict) -> dict:
        r = requests.post(
            f"{self.endpoint}/contentsafety/text:{operation}",
            params={"api-version": CONTENT_SAFETY_API},
            headers={"Authorization": f"Bearer {self._token()}",
                     "Content-Type": "application/json"},
            json=body, timeout=self.timeout,
        )
        # Fail closed: an unscreened request must never reach the model.
        if r.status_code != 200:
            raise RuntimeError(f"Content Safety {operation} failed: {r.status_code} {r.text}")
        return r.json()

    def prompt_shields(self, user_prompt: str, docs: list[str]) -> list[str]:
        res = self._content_safety("shieldPrompt", {"userPrompt": user_prompt, "documents": docs})
        reasons = []
        if res.get("userPromptAnalysis", {}).get("attackDetected"):
            reasons.append("jailbreak")
        for i, d in enumerate(res.get("documentsAnalysis", [])):
            if d.get("attackDetected"):
                reasons.append(f"indirect_attack(doc {i})")
        return reasons

    def harm(self, text: str) -> list[str]:
        if not text.strip():
            return []
        res = self._content_safety("analyze", {"text": text, "outputType": "FourSeverityLevels"})
        return [f"{c['category'].lower()}(severity {c['severity']})"
                for c in res.get("categoriesAnalysis", [])
                if c.get("severity", 0) >= self.severity_floor]

    def _pii(self, text: str, categories: list[str] | None = None):
        kwargs = {"language": "en"}
        if categories:
            kwargs["categories_filter"] = categories
        result = self._language.recognize_pii_entities([text], **kwargs)[0]
        if result.is_error:
            raise RuntimeError(f"PII screening failed: {result.error}")
        return result

    def redact(self, text: str) -> tuple[str, list[str]]:
        r = self._pii(text, INPUT_REDACT_CATEGORIES)
        return r.redacted_text, sorted({e.category for e in r.entities})

    def detect_pii(self, text: str) -> list[str]:
        """Blocking PII categories present in text (BLOCK_CATEGORIES)."""
        if not text.strip():
            return []
        return sorted({e.category for e in self._pii(text).entities} & self.output_block)

    def _pii_reasons(self, texts: list[str]) -> list[str]:
        found = sorted({c for t in texts for c in self.detect_pii(t)})
        return [f"pii:{'/'.join(found)}"] if found else []

    # ---------------------------------------------------------------- screens
    def screen_input(self, question: str, docs: list[str] | None = None,
                     redact: bool = True) -> Verdict:
        """redact=True: replace PII with *** and continue (recommended).
        redact=False: block the request if blocking PII/PCI is present.
        Then Prompt Shields and harm analysis run (in parallel)."""
        docs = list(docs or [])
        notes: list[str] = []
        futures = []
        if redact:
            question, found = self.redact(question)
            if found:
                notes.append(f"redacted from question: {', '.join(found)}")
            cleaned = []
            for d in docs:
                red, found = self.redact(d)
                if found:
                    notes.append(f"redacted from document: {', '.join(found)}")
                cleaned.append(red)
            docs = cleaned
        else:
            futures.append(self._pool.submit(self._pii_reasons, [question, *docs]))

        futures += [
            self._pool.submit(self.prompt_shields, question, docs),
            self._pool.submit(self.harm, "\n".join([question, *docs])),
        ]
        reasons = [r for f in futures for r in f.result()]
        return Verdict(not reasons, reasons, notes, question, docs)

    def screen_output(self, text: str) -> Verdict:
        """Harm analysis and PII/PCI detection on a model reply."""
        futures = [
            self._pool.submit(self.harm, text),
            self._pool.submit(self._pii_reasons, [text]),
        ]
        reasons = [r for f in futures for r in f.result()]
        return Verdict(not reasons, reasons, text=text)
