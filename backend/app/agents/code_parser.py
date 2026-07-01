"""Code parser agent logic using ShieldLabsAgent."""

import logging
from typing import Any

from crewai import Task, Crew

from app.agents.base import ShieldLabsAgent

logger = logging.getLogger("shieldlabs.agents.code_parser")


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

    def analyze(self, file_path: str, source_code: str) -> str:
        """
        Runs a real CrewAI task asking the agent to summarize the
        structure of a code file before scanning proceeds.

        Args:
            file_path: path of the file being analyzed (for context)
            source_code: the raw source code

        Returns:
            A short structural summary as plain text.
        """
        if self.agent is None:
            logger.warning("CrewAI agent not initialized; skipping structural analysis.")
            return "Structural analysis unavailable (CrewAI not initialized)."

        # Keep the snippet bounded so we don't blow the context window
        # on huge files.
        snippet = source_code[:3000]

        task = Task(
            description=(
                "Analyze the structure of this code file at path '" + file_path + "'.\n\n"
                "Code:\n```\n" + snippet + "\n```\n\n"
                "List the functions, classes, and imports present. "
                "Keep your answer to 3-5 concise bullet points."
            ),
            expected_output="A short bulleted list of the file's functions, classes, and imports.",
            agent=self.agent,
        )

        crew = Crew(agents=[self.agent], tasks=[task], verbose=False)
        result = crew.kickoff()
        logger.info("Code Parser Agent completed structural analysis of %s", file_path)
        return str(result)