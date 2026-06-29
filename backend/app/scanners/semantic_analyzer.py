"""
scanners/semantic_analyzer.py

Uses Qwen 2.5 (via Ollama) to review low-confidence findings from
pattern_detector.py and decide: real vulnerability or false positive?

Only findings with confidence < LLM_REVIEW_THRESHOLD get sent to the LLM.
High-confidence findings (hardcoded secrets, disabled JWT verify, etc.)
skip this step entirely — we already trust them.
"""

import json
import logging
import requests

from app.config import settings

logger = logging.getLogger("shieldlabs.semantic_analyzer")

# Findings below this confidence go to the LLM for review
LLM_REVIEW_THRESHOLD = 0.7

OLLAMA_URL = f"{settings.ollama_base_url}/api/generate"
OLLAMA_MODEL = settings.ollama_model


# ─────────────────────────────────────────────
# PROMPT BUILDER
# ─────────────────────────────────────────────

def _build_prompt(finding: dict) -> str:
    return f"""You are a senior application security engineer reviewing a potential vulnerability finding.

Vulnerability type: {finding['vuln_type']}
File: {finding['file']}
Line {finding['line']}: {finding['code_snippet']}
Reason flagged: {finding['reason']}

Is this a real security vulnerability, or a false positive?

Reply with ONLY a JSON object, nothing else:
{{"verdict": "CONFIRM" or "FALSE_POSITIVE" or "UNCERTAIN", "explanation": "one sentence"}}"""


# ─────────────────────────────────────────────
# SINGLE FINDING REVIEW
# ─────────────────────────────────────────────

def review_finding(finding: dict) -> dict:
    """
    Sends one finding to Qwen 2.5 and gets a verdict.
    Returns the finding with llm_verdict and llm_explanation added.
    """
    prompt = _build_prompt(finding)

    try:
        response = requests.post(OLLAMA_URL, json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1}  # low temp = more consistent verdicts
        }, timeout=60)

        response.raise_for_status()
        raw_text = response.json().get("response", "").strip()

        # Strip markdown fences if Qwen wraps it anyway
        if raw_text.startswith("```"):
            raw_text = raw_text.strip("`").strip()
            if raw_text.startswith("json"):
                raw_text = raw_text[4:].strip()

        parsed = json.loads(raw_text)
        verdict = parsed.get("verdict", "UNCERTAIN").upper()
        explanation = parsed.get("explanation", "No explanation provided.")

        if verdict not in ("CONFIRM", "FALSE_POSITIVE", "UNCERTAIN"):
            verdict = "UNCERTAIN"

    except requests.exceptions.ConnectionError:
        logger.warning("Ollama not reachable — marking as UNCERTAIN")
        verdict = "UNCERTAIN"
        explanation = "LLM unavailable; manual review needed."

    except (json.JSONDecodeError, KeyError) as e:
        logger.warning(f"Could not parse LLM response: {e} | raw: {raw_text!r}")
        verdict = "UNCERTAIN"
        explanation = "LLM response unparseable; manual review needed."

    finding = finding.copy()
    finding["llm_verdict"] = verdict
    finding["llm_explanation"] = explanation
    return finding


# ─────────────────────────────────────────────
# BATCH REVIEW
# ─────────────────────────────────────────────

def filter_findings_with_llm(findings: list[dict]) -> list[dict]:
    """
    Takes the full list of pattern_detector findings.
    - High confidence (>= threshold): passed through as CONFIRM automatically
    - Low confidence (< threshold): sent to Qwen for review
    - FALSE_POSITIVE verdicts are dropped from the final list

    Returns only confirmed (or uncertain) findings.
    """
    confirmed = []

    for finding in findings:
        if finding["confidence"] >= LLM_REVIEW_THRESHOLD:
            # Trust the regex on high-confidence hits
            finding = finding.copy()
            finding["llm_verdict"] = "CONFIRM"
            finding["llm_explanation"] = "High-confidence pattern match; skipped LLM review."
            confirmed.append(finding)
        else:
            logger.info(f"Sending to LLM for review: {finding['vuln_type']} line {finding['line']}")
            reviewed = review_finding(finding)

            if reviewed["llm_verdict"] == "FALSE_POSITIVE":
                logger.info(f"LLM dismissed as false positive: {finding['vuln_type']} line {finding['line']}")
                continue  # drop it

            confirmed.append(reviewed)

    logger.info(f"After LLM filter: {len(confirmed)}/{len(findings)} findings kept")
    return confirmed