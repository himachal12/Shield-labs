"""
scanners/fix_generator.py

Day 5 — Fix Generation.

Takes a confirmed vulnerability finding and asks the LLM to produce:
- a corrected code snippet
- a plain-English explanation
- a unified diff (before/after patch view)
- a confidence score for the FIX itself (not the detection)
- a breaking-change risk assessment ("Low" / "Medium" / "High")

Routes through app.utils.llm.ask_llm() so it inherits Groq->Ollama
fallback, retries, and logging instead of calling Ollama directly.
"""

import difflib
import json
import logging
from typing import Optional

from app.utils.llm import ask_llm

logger = logging.getLogger("shieldlabs.fix_generator")

VALID_RISK_LEVELS = {"low", "medium", "high"}


def _build_prompt(finding: dict) -> str:
    """Builds the prompt asking the LLM for a structured fix."""
    code = finding.get("code_snippet") or finding.get("vulnerable_code") or ""
    vuln_type = finding.get("vuln_type", "Unknown vulnerability")
    file_path = finding.get("file") or finding.get("file_path") or "unknown file"

   return f"""You are a senior application security engineer. Fix this vulnerability.

Vulnerability type: {vuln_type}
File: {file_path}
Vulnerable code:
{{
  "patched_code": "the corrected code, same language, minimal change",
  "explanation": "2-4 sentences explaining the fix",
  "confidence": 0.0 to 1.0 (how confident you are this fix is correct and complete),
  "breaking_change_risk": "Low" or "Medium" or "High" (chance this fix changes behavior)
}}
"""


def _parse_llm_json(raw: str) -> Optional[dict]:
    """Safely parses the LLM's JSON response, tolerating stray markdown fences."""
    if not raw:
        return None
    text = raw.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                logger.warning("Could not parse LLM JSON even after trimming.")
        return None


def _make_unified_diff(original: str, patched: str, file_path: str) -> str:
    """Generates a clean unified diff between original and patched code."""
    original_lines = (original or "").splitlines(keepends=True)
    patched_lines = (patched or "").splitlines(keepends=True)
    diff = difflib.unified_diff(
        original_lines,
        patched_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        lineterm="",
    )
    return "\n".join(diff)


def generate_fix(finding: dict) -> dict:
    """
    Generates a fix for a single finding.

    Args:
        finding: dict from pattern_detector/semantic_analyzer, expected to
                  contain at least vuln_type, code_snippet (or vulnerable_code),
                  and file (or file_path).

    Returns:
        The same finding dict, merged with:
            fixed_code, fix_explanation, unified_diff,
            fix_confidence, breaking_change_risk
        On failure, these keys are set to None and an "fix_error" key is added.
    """
    original_code = finding.get("code_snippet") or finding.get("vulnerable_code") or ""
    file_path = finding.get("file") or finding.get("file_path") or "unknown"

    prompt = _build_prompt(finding)
    result = ask_llm(prompt, max_tokens=1024, prefer_local=True)

    if not result.get("success"):
        logger.error(f"Fix generation failed for {finding.get('vuln_type')}: {result.get('error')}")
        return {
            **finding,
            "fixed_code": None,
            "fix_explanation": None,
            "unified_diff": None,
            "fix_confidence": None,
            "breaking_change_risk": None,
            "fix_error": result.get("error"),
        }

    parsed = _parse_llm_json(result["response"])
    if not parsed:
        logger.warning(f"Could not parse fix JSON for {finding.get('vuln_type')}; raw response kept as explanation.")
        return {
            **finding,
            "fixed_code": None,
            "fix_explanation": result["response"],
            "unified_diff": None,
            "fix_confidence": None,
            "breaking_change_risk": None,
            "fix_error": "unparseable_response",
        }

    patched_code = parsed.get("patched_code", "")
    risk = str(parsed.get("breaking_change_risk", "Medium")).strip().capitalize()
    if risk.lower() not in VALID_RISK_LEVELS:
        risk = "Medium"

    confidence = parsed.get("confidence", 0.5)
    try:
        confidence = max(0.0, min(1.0, float(confidence)))
    except (TypeError, ValueError):
        confidence = 0.5

    return {
        **finding,
        "fixed_code": patched_code,
        "fix_explanation": parsed.get("explanation"),
        "unified_diff": _make_unified_diff(original_code, patched_code, file_path),
        "fix_confidence": confidence,
        "breaking_change_risk": risk,
    }


def generate_fixes_for_all(findings: list[dict]) -> list[dict]:
    """
    Generates fixes for a list of findings, one at a time.

    Args:
        findings: list of finding dicts (post semantic-analyzer filtering)

    Returns:
        Same list, each item enriched with fix fields.
    """
    logger.info(f"Generating fixes for {len(findings)} findings...")
    enriched = [generate_fix(f) for f in findings]
    succeeded = sum(1 for f in enriched if f.get("fixed_code"))
    logger.info(f"Fix generation complete: {succeeded}/{len(findings)} succeeded.")
    return enriched