from app.utils.pdf_generator_html import generate_pdf_report_html

scan = {"scan_id": "scan_html_test1", "target": "test-repoo-shieldlabs", "scan_type": "code"}

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
    {
        "vuln_type": "Hardcoded Secret", "severity": "high", "file": "app.py", "line": 10,
        "code": 'API_KEY = "sk-live-51H8xJ2eZvKYlo2C0FAKEKEYFORTESTING"',
        "fix": "API_KEY = os.getenv('SHIELDLABS_API_KEY')",
        "cvss_score": 8.1,
    },
]

chains = [
    {"severity": "critical", "time_to_exploit": "2 hours",
     "description": "SQL injection combined with an exposed database port allows direct DB access, bypassing the application layer entirely.",
     "impact": "Full database compromise."}
]

path = generate_pdf_report_html(scan, findings, chains)
print("PDF saved to:", path)
