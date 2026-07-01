"""
agents/cross_domain_analyzer.py

Day 8 — Cross-Domain Analysis Agent.

Looks across a code scan's findings and a web scan's findings for the
same target, and identifies attack chains: cases where a code-level
weakness and a web-level exposure compound into a worse combined risk
than either represents alone.
"""

import json
import logging
import re
from typing import Any

from crewai import Task, Crew

from app.agents.base import ShieldLabsAgent

logger = logging.getLogger("shieldlabs.agents.cross_domain_analyzer")


class CrossDomainAnalysisAgent(ShieldLabsAgent):
    """Agent for identifying compounded-risk attack chains across code and web findings."""

    def __init__(self, llm: Any = None):
        super().__init__(
            name="Cross-Domain Analysis Agent",
            role="Attack chain and compounded-risk analyst",
            goal="Identify how code-level vulnerabilities and web-level exposures combine into worse real-world attack paths",
            backstory="You are a red-team lead who thinks in attack chains, not isolated findings — you know that a medium-severity bug next to an exposed service can become a critical path to full compromise.",
            llm=llm,
        )

    def identify_chains(self, code_findings: list[dict], web_findings: list[dict]) -> list[dict]:
        """
        Analyzes code + web findings together and returns any attack
        chains identified. Empty list is a valid, common result — most
        finding pairs won't chain together.

        Args:
            code_findings: findings from a code scan (with finding_id, vuln_type, description)
            web_findings: findings from a web scan (same shape)

        Returns:
            list of dicts: {finding_ids: [...], severity, description, time_to_exploit, impact}
        """
        if self.agent is None or not code_findings or not web_findings:
            return []

        code_summary = "\n".join(
            "- [" + f.get("finding_id", "?") + "] " + f.get("vuln_type", "Unknown") + ": " + (f.get("description") or f.get("reason") or "")
            for f in code_findings
        )
        web_summary = "\n".join(
            "- [" + f.get("finding_id", "?") + "] " + f.get("vuln_type", "Unknown") + ": " + (f.get("description") or f.get("reason") or "")
            for f in web_findings
        )

        task = Task(
            description=(
                "Here are CODE findings from a source code scan:\n" + code_summary + "\n\n"
                "Here are WEB findings from an infrastructure scan of the same target:\n" + web_summary + "\n\n"
                "Identify any attack CHAINS: cases where a code finding and a web finding "
                "combine into a worse compounded risk than either alone (e.g. a SQL injection "
                "in the app plus an exposed database port bypassing the app entirely).\n\n"
                "Only report GENUINE compounding relationships, not coincidental co-occurrence. "
                "If none exist, return an empty list — that is a valid and common answer.\n\n"
                "Respond with ONLY a JSON array (no markdown fences, no extra text), each item shaped as:\n"
                "{\n"
                '  "finding_ids": ["<code finding_id>", "<web finding_id>"],\n'
                '  "severity": "critical" | "high" | "medium",\n'
                '  "description": "<how the chain works, step by step>",\n'
                '  "time_to_exploit": "<short estimate>",\n'
                '  "impact": "<real-world consequence if chained>"\n'
                "}\n"
                "Return [] if no genuine chains exist."
            ),
            expected_output="A JSON array of attack chain objects, or an empty array.",
            agent=self.agent,
        )

        crew = Crew(agents=[self.agent], tasks=[task], verbose=False)

        try:
            raw = str(crew.kickoff())
            parsed = _parse_json_array(raw)
            if parsed is None:
                logger.warning("Could not parse cross-domain chain JSON; returning no chains.")
                return []
            return parsed
        except Exception:
            logger.exception("Cross-Domain Analysis Agent failed; returning no chains.")
            return []


def _parse_json_array(raw: str):
    if not raw:
        return None
    text = raw.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    try:
        result = json.loads(text)
        return result if isinstance(result, list) else None
    except json.JSONDecodeError:
        match = re.search(r"\[.*\]", text, re.DOTALL)
        if match:
            try:
                result = json.loads(match.group(0))
                return result if isinstance(result, list) else None
            except json.JSONDecodeError:
                return None
        return None