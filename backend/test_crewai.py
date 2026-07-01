from crewai import Agent, Task, Crew, LLM

llm = LLM(
    model="ollama/qwen2.5-coder:7b",
    base_url="http://localhost:11434",
)

tester_agent = Agent(
    role="Test Agent",
    goal="Prove that CrewAI can call the local LLM successfully",
    backstory="You are a simple diagnostic agent used to verify infrastructure.",
    llm=llm,
    verbose=True,
)

test_task = Task(
    description="Reply with exactly the words: CrewAI is working.",
    expected_output="The exact phrase: CrewAI is working.",
    agent=tester_agent,
)

crew = Crew(agents=[tester_agent], tasks=[test_task], verbose=True)

result = crew.kickoff()
print("RESULT:", result)