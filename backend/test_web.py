from app.scanners.web_scanner import run_web_recon

results = run_web_recon("example.com")
for finding in results:
    print(finding)