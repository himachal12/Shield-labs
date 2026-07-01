"""
agents/severity_reasoning.py

Day 7-8 — Severity Reasoning Agent.

Combines the deterministic CVSS 3.1 score (cvss_calculator.py) with
an LLM-driven exploitability assessment, giving each finding a
business-context severity picture: not just "how bad in theory" but
"how easily could someone actually exploit this in a typical startup app".
"""

import json
import logging
import re
from typing import Any

from crewai import Task, Crew

from app.agents.base import ShieldLabsAgent
from app.scanners.cvss_calculator import calculate_cvss

logger = logging.getLogger("shieldlabs.agents.severity_reasoning")


class SeverityReasoningAgent(ShieldLabsAgent):
    """Agent for combining CVSS scoring with real-world exploitability reasoning."""

    def __init__(self, llm: Any = None):
        super().__init__(
            name="Severity Reasoning Agent",
            role="Vulnerability risk and exploitability analyst",
            goal="Assess real-world exploitability and business impact of security findings, on top of their CVSS score",
            backstory="You are a senior penetration tester who has assessed hundreds of startup applications and knows how vulnerabilities actually get exploited in practice, not just in theory.",
            llm=llm,
        )

    def assess(self, finding: dict) -> dict:
        """
        Computes deterministic CVSS, then asks the LLM for
        exploitability/time-to-exploit/business-impact context.

        Args:
            finding: a finding dict with at least vuln_type and reason

        Returns:
            dict with cvss_score, cvss_vector, exploitability (1-10),
            time_to_exploit, business_impact — degrades gracefully to
            CVSS-only if the LLM call fails or returns unparseable output.
        """
        vuln_type = finding.get("vuln_type", "Unknown")
        cvss = calculate_cvss(vuln_type)

        result = dict(cvss)
        result["exploitability"] = None
        result["time_to_exploit"] = None
        result["business_impact"] = None

        if self.agent is None:
            logger.warning("CrewAI agent not initialized; returning CVSS-only assessment.")
            return result

        description = finding.get("reason") or finding.get("description") or vuln_type

        task = Task(
            description=(
                "Given this vulnerability: " + description + "\n\n"
                "CVSS base score: " + str(cvss["cvss_score"]) + " (" + cvss["cvss_vector"] + ")\n\n"
                "In a typical startup web application, how easily could an attacker "
                "exploit this? Consider time required, prerequisites, and skill level.\n\n"
                "Respond with ONLY a JSON object (no markdown fences, no extra text):\n"
                "{\n"
                '  "exploitability": <integer 1-10>,\n'
                '  "time_to_exploit": "<short estimate, e.g. \'5 minutes\' or \'2 hours\'>",\n'
                '  "business_impact": "<one sentence on real-world consequence>"\n'
                "}"
            ),
            expected_output="A JSON object with exploitability, time_to_exploit, and business_impact.",
            agent=self.agent,
        )

        crew = Crew(agents=[self.agent], tasks=[task], verbose=False)

        try:
            raw = str(crew.kickoff())
            parsed = _parse_json_response(raw)
            if parsed:
                result["exploitability"] = parsed.get("exploitability")
                result["time_to_exploit"] = parsed.get("time_to_exploit")
                result["business_impact"] = parsed.get("business_impact")
            else:
                logger.warning("Could not parse exploitability JSON for %s; keeping CVSS-only.", vuln_type)
        except Exception:
            logger.exception("Severity Reasoning Agent failed for %s; keeping CVSS-only.", vuln_type)

        return result


def _parse_json_response(raw: str):
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
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                return None
        return None