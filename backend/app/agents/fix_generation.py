"""Fix generation agent logic using ShieldLabsAgent."""

from typing import Any
from app.agents.base import ShieldLabsAgent


class FixGenerationAgent(ShieldLabsAgent):
    """Agent for generating secure code fixes for security vulnerabilities."""

    def __init__(self, llm: Any = None):
        super().__init__(
            name="Fix Generation Agent",
            role="Security vulnerability remediation specialist",
            goal="Generate safe, secure, and syntax-valid code fixes for identified security findings",
            backstory="You are a senior security engineer with deep expertise in secure coding standards (OWASP, CWE) and code patching.",
            llm=llm,
        )
