"""Base agent abstraction used by ShieldLabs analysis agents."""

from typing import Any

try:
    from crewai import Agent
except ImportError:
    Agent = None


class ShieldLabsAgent:
    def __init__(self, name: str, role: str, goal: str, backstory: str, llm: Any = None):
        self.name = name
        self.role = role
        self.goal = goal
        self.backstory = backstory
        self.llm = llm
        self.agent = None
        if Agent is not None:
            self.agent = Agent(role=role, goal=goal, backstory=backstory, llm=llm, verbose=True)

    def __repr__(self) -> str:
        return f"<ShieldLabsAgent {self.name}>"
