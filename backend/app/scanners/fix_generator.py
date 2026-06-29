"""
scanners/fix_generator.py

Sends confirmed vulnerability findings to Qwen 2.5 and asks it
to generate a secure fix for the vulnerable code snippet.
"""

import json
import logging
import requests

from app.config import settings

logger = logging.getLogger("shieldlabs.fix_generator")

OLLAMA_URL = f"{settings.ollama_base_url}/api/generate"
OLLAMA_MODEL = settings.ollama_model


# ─────────────────────────────────────────────
# PROMPT BUILDER
# ─────────────────────────────────────────────

def _build_fix_prompt(finding: dict) -> str:
    return f"""You are a senior security engineer. Write a secure fix for this vulnerability.

Vulnerability: {finding['vuln_type']}
Vulnerable code (line {finding['line']}):
{finding['code_snippet']}

Reason it's dangerous: {finding['reason']}

Reply with ONLY a JSON object, nothing else:
{{"fixed_code": "the secure replacement code", "fix_explanation": "one sentence why this is safer"}}"""


# ─────────────────────────────────────────────
# SINGLE FINDING FIX
# ─────────────────────────────────────────────

def generate_fix(finding: dict) -> dict:
    """
    Asks Qwen 2.5 to write a secure fix for one finding.
    Returns the finding with fix_code and fix_explanation added.
    """
    prompt = _build_fix_prompt(finding)

    try:
        response = requests.post(OLLAMA_URL, json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2}
        }, timeout=90)

        response.raise_for_status()
        raw_text = response.json().get("response", "").strip()

        # Strip markdown fences if present
        if raw_text.startswith("```"):
            raw_text = raw_text.strip("`").strip()
            if raw_text.startswith("json"):
                raw_text = raw_text[4:].strip()

        parsed = json.loads(raw_text)
        fix_code = parsed.get("fixed_code", "# Fix unavailable")
        fix_explanation = parsed.get("fix_explanation", "No explanation provided.")

    except requests.exceptions.ConnectionError:
        logger.warning("Ollama not reachable — fix unavailable")
        fix_code = "# Ollama unavailable — fix manually"
        fix_explanation = "LLM unavailable; manual remediation needed."

    except (json.JSONDecodeError, KeyError) as e:
        logger.warning(f"Could not parse fix response: {e} | raw: {raw_text!r}")
        fix_code = "# Could not parse fix"
        fix_explanation = "LLM response unparseable; manual review needed."

    finding = finding.copy()
    finding["fix_code"] = fix_code
    finding["fix_explanation"] = fix_explanation
    return finding


# ─────────────────────────────────────────────
# BATCH FIX GENERATION
# ─────────────────────────────────────────────

def generate_fixes_for_all(findings: list[dict]) -> list[dict]:
    """
    Generates fixes for every confirmed finding.
    FALSE_POSITIVE findings should already be filtered out before
    calling this — pass the output of filter_findings_with_llm().

    Returns the full list with fix_code and fix_explanation added.
    """
    results = []
    for i, finding in enumerate(findings, start=1):
        logger.info(f"Generating fix {i}/{len(findings)}: {finding['vuln_type']}")
        fixed = generate_fix(finding)
        results.append(fixed)

    logger.info(f"Fix generation complete for {len(results)} findings")
    return results