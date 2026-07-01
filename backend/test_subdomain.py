from app.scanners.web_scanner import enumerate_subdomains

results = enumerate_subdomains("nmap.org")
for finding in results:
    print(finding)