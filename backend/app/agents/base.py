"""Base agent abstraction used by ShieldLabs analysis agents."""

import logging
from typing import Any

from app.config import settings

try:
    from crewai import Agent, LLM
except ImportError:
    Agent = None
    LLM = None

logger = logging.getLogger("shieldlabs.agents.base")


def _default_llm():
    """
    Builds the default local Ollama LLM used by ShieldLabs agents when
    no llm is explicitly provided. Matches the exact config already
    proven working in test_crewai.py.
    """
    if LLM is None:
        return None
    return LLM(
        model="ollama/" + settings.ollama_model,
        base_url=settings.ollama_base_url,
    )


class ShieldLabsAgent:
    def __init__(self, name: str, role: str, goal: str, backstory: str, llm: Any = None):
        self.name = name
        self.role = role
        self.goal = goal
        self.backstory = backstory
        self.llm = llm if llm is not None else _default_llm()
        self.agent = None
        if Agent is not None:
            self.agent = Agent(role=role, goal=goal, backstory=backstory, llm=self.llm, verbose=True)
        else:
            logger.warning("crewai.Agent unavailable; %s will not execute real tasks.", name)

    def __repr__(self) -> str:
        return f"<ShieldLabsAgent {self.name}>"