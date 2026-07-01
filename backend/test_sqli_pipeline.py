from app.scanners.sqlmap_pipeline import run_sqli_deep_scan
import time

start = time.time()
findings = run_sqli_deep_scan("http://127.0.0.1:5555")
elapsed = time.time() - start

print(f"Completed in {elapsed:.1f}s")
print(f"Total findings: {len(findings)}")
for f in findings:
    print(f["vuln_type"], "-", f["url"])
