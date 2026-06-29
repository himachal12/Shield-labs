"""
Base Agent class for CrewAI
All agents inherit from this
"""

from crewai import Agent, Task
from typing import Optional

class ShieldLabsAgent:
    """
    Base agent for ShieldLabs
    Wraps CrewAI Agent with custom functionality
    """
    
    def __init__(
        self,
        name: str,
        role: str,
        goal: str,
        backstory: str,
        llm=None
    ):
        """
        Initialize agent
        
        Args:
            name: Agent name
            role: Agent's role (e.g., "Code Security Expert")
            goal: What agent aims to do
            backstory: Agent's background/expertise
            llm: Language model instance
        """
        self.name = name
        self.role = role
        self.goal = goal
        self.backstory = backstory
        self.llm = llm
        
        # Create CrewAI agent
        self.agent = Agent(
            role=role,
            goal=goal,
            backstory=backstory,
            llm=llm,
            verbose=True
        )
    
    def __repr__(self):
        return f"<ShieldLabsAgent {self.name}>"