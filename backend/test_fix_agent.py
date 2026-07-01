from app.agents.fix_generation import FixGenerationAgent

agent = FixGenerationAgent()

finding = {
    "vuln_type": "SQL Injection",
    "code_snippet": 'query = "SELECT * FROM users WHERE name = \'" + username + "\'"',
    "fixed_code": 'query = "SELECT * FROM users WHERE name = %s"',
}

result = agent.review_fix(finding)
print("FIX REVIEW:")
print(result)