"""Code parser agent logic using ShieldLabsAgent."""

from typing import Any
from app.agents.base import ShieldLabsAgent


class CodeParserAgent(ShieldLabsAgent):
    """Agent for parsing code structure, functions, classes, and imports."""

    def __init__(self, llm: Any = None):
        super().__init__(
            name="Code Parser Agent",
            role="Code structure parser and syntax analyzer",
            goal="Extract functions, classes, and imports from code files, and analyze their relationships",
            backstory="You are an expert code architect who understands programming languages, ASTs, and project structures.",
            llm=llm,
        )
