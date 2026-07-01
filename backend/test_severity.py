from app.agents.severity_reasoning import SeverityReasoningAgent

agent = SeverityReasoningAgent()

finding = {
    "vuln_type": "SQL Injection",
    "reason": "String concatenation in SQL query allows injection via the username parameter.",
}

result = agent.assess(finding)
print("SEVERITY ASSESSMENT:")
print(result)
