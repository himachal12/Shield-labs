from app.scanners.cvss_calculator import calculate_cvss

for vuln in ["SQL Injection", "Missing Security Header: Referrer-Policy", "Command Injection", "Weak Hashing", "Something Unknown"]:
    result = calculate_cvss(vuln)
    print(vuln, "->", result)
