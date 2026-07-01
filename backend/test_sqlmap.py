from app.scanners.sqlmap_scanner import run_sqlmap_scan
import time

start = time.time()
findings = run_sqlmap_scan("http://127.0.0.1:5555/user?id=1")
elapsed = time.time() - start

print(f"Completed in {elapsed:.1f}s")
print(f"Findings: {len(findings)}")
for f in findings:
    print(f)
