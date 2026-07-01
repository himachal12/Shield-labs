from app.scanners.nuclei_scanner import run_nuclei_scan
import time

start = time.time()
findings = run_nuclei_scan("http://scanme.nmap.org")
elapsed = time.time() - start

print(f"Completed in {elapsed:.1f}s")
print(f"Findings: {len(findings)}")
for f in findings:
    print(f)
