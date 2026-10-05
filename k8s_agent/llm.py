"""
Optional LLM augmentation layer using Gemini / Google GenAI.
Supports zero-dependency REST queries using standard library urllib when API key is present.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import List, Optional

from .models import EvidenceItem, Finding, RootCause


class LLMAugmentedReasoner:
    """Enhances root cause analysis with LLM reasoning when API key is available."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-2.5-flash",
    ):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        self.model = model

    @property
    def is_available(self) -> bool:
        return bool(self.api_key)

    def enrich_analysis(
        self,
        raw_logs_snippet: str,
        findings: List[Finding],
        evidence: List[EvidenceItem],
        base_root_cause: Optional[RootCause],
    ) -> Optional[RootCause]:
        """Queries Gemini to synthesize a nuanced root cause from gathered evidence."""
        if not self.is_available:
            return base_root_cause

        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"

        evidence_summary = "\n".join(
            f"- [Line {e.line_number}] [{e.category}] {e.raw_log.strip()}"
            for e in evidence[:15]
        )

        prompt = f"""You are a Principal Kubernetes Site Reliability Engineer investigating an incident.
Review the following log evidence and findings:

Findings:
{[f.title for f in findings]}

Key Supporting Evidence:
{evidence_summary}

Raw Log Excerpt:
{raw_logs_snippet[:2000]}

Respond ONLY with valid JSON with the following structure:
{{
  "primary_cause": "Short concise root cause title",
  "explanation": "2-3 sentences explaining the technical failure mechanism based strictly on the evidence",
  "causal_chain": ["Step 1...", "Step 2...", "Step 3..."],
  "confidence": 0.95
}}
"""

        payload = {
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json",
            },
        }

        try:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode("utf-8"))
                text = result["candidates"][0]["content"]["parts"][0]["text"]
                parsed = json.loads(text)

                return RootCause(
                    primary_cause=parsed.get("primary_cause", base_root_cause.primary_cause if base_root_cause else "Unknown"),
                    explanation=parsed.get("explanation", base_root_cause.explanation if base_root_cause else ""),
                    confidence=float(parsed.get("confidence", 0.9)),
                    causal_chain=parsed.get("causal_chain", base_root_cause.causal_chain if base_root_cause else []),
                    key_evidence=evidence[:3],
                )
        except Exception:
            # Fall back gracefully to heuristic root cause
            return base_root_cause
