from app.agents.cross_domain_analyzer
import CrossDomainAnalysisAgent

agent = CrossDomainAnalysisAgent()

code_findings = [
    {"finding_id": "find_sqli_001", "vuln_type": "SQL Injection", "description": "String concatenation in SQL query in app.py"},
    {"finding_id": "find_secret_001", "vuln_type": "Hardcoded Secret", "description": "Hardcoded API key found in app.py"},
]

web_findings = [
    {"finding_id": "find_port_001", "vuln_type": "Risky Open Port: 3306 (MySQL)", "description": "MySQL database port exposed to the internet with no authentication detected"},
    {"finding_id": "find_port_002", "vuln_type": "Open Port: 22", "description": "SSH port open"},
]

chains = agent.identify_chains(code_findings, web_findings)
print("CHAINS FOUND:", len(chains))
for c in chains:
    print(c)
