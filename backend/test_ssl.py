from app.scanners.web_scanner import check_ssl_tls

results = check_ssl_tls("nmap.org")
for finding in results:
    print(finding)
if not results:
    print("No SSL/TLS issues found (or site not on HTTPS).")