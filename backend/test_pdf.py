from app.utils.pdf_generator import generate_pdf_report

scan = {"scan_id": "scan_test123", "target": "test-repoo-shieldlabs", "scan_type": "code", "total_findings": 2}

findings = [
    {
        "vuln_type": "SQL Injection", "severity": "critical", "file": "app.py", "line": 4,
        "code": "query = \"SELECT * FROM users WHERE name = '\" + username + \"'\"",
        "fix": "query = \"SELECT * FROM users WHERE name = %s\"",
        "cvss_score": 9.3, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
        "agent_review_notes": "The proposed fix is safe and complete.",
        "business_impact": "Complete data loss or theft.",
    },
    {
        "vuln_type": "Weak Hashing", "severity": "medium", "file": "auth.py", "line": 4,
        "code": "return hashlib.md5(password.encode()).hexdigest()",
        "fix": "return hashlib.sha256(password.encode()).hexdigest()",
        "cvss_score": 5.8, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
]

chains = [
    {"severity": "critical", "time_to_exploit": "2 hours", "description": "SQL injection combined with exposed database port allows direct DB access.", "impact": "Full database compromise."}
]

path = generate_pdf_report(scan, findings, chains)
print("PDF saved to:", path)
