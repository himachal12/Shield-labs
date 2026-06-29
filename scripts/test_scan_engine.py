"""Scan Engine validation script for ShieldLabs."""

import sys
from pathlib import Path
from unittest.mock import patch

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / 'backend'))
sys.path.insert(0, str(ROOT_DIR / 'backend' / 'app'))

from app.scan_engine import scan_local_file, scan_web_domain
from app.models.database import init_db

def test_scan_engine():
    print("--- SCAN ENGINE TESTS ---")
    
    vulnerable_app_path = ROOT_DIR / "tests" / "samples" / "vulnerable_app.py"

    # We mock out the LLM calls (semantic filter & fix generation) to run a fast offline end-to-end integration test
    def mock_filter(findings):
        # return findings with CONFIRM / explanation populated
        results = []
        for f in findings:
            fc = f.copy()
            fc["llm_verdict"] = "CONFIRM"
            fc["llm_explanation"] = "Mocked explanation"
            results.append(fc)
        return results

    def mock_fixes(findings):
        # return findings with fix_code / fix_explanation populated
        results = []
        for f in findings:
            fc = f.copy()
            fc["fix_code"] = f"# Fixed: secure version of {f['code_snippet']}"
            fc["fix_explanation"] = "Use a safer library."
            results.append(fc)
        return results

    init_db()

    print("Running end-to-end local file scan...")
    with patch("app.scan_engine.filter_findings_with_llm", side_effect=mock_filter), \
         patch("app.scan_engine.generate_fixes_for_all", side_effect=mock_fixes):
        
        result = scan_local_file(str(vulnerable_app_path))
        
        # Verify scan structure
        if "scan" in result and "findings" in result:
            print("  ✅ PASS: Local file scan returned correct high-level keys.")
        else:
            print(f"  ❌ FAIL: Local file scan result missing key structures: {result}")
            return [], [("Scan local file structural validation", "Missing 'scan' or 'findings'")]

        scan_info = result["scan"]
        findings = result["findings"]

        if scan_info.get("status") == "completed":
            print("  ✅ PASS: Scan status marked as completed.")
        else:
            print(f"  ❌ FAIL: Scan status was: {scan_info.get('status')}")

        if len(findings) > 0:
            print(f"  ✅ PASS: Scan findings successfully populated. Found {len(findings)} findings.")
            f = findings[0]
            if "finding_id" in f and "vuln_type" in f and "severity" in f and "file" in f and "line" in f and "code" in f and "fix" in f:
                print("  ✅ PASS: Findings matched expected result schema.")
            else:
                print(f"  ❌ FAIL: Finding schema does not match. Finding: {f}")
        else:
            print("  ❌ FAIL: No findings found in local file scan.")

    print("Running web scan...")
    web_result = scan_web_domain("example.com")
    if web_result.get("scan", {}).get("status") == "completed":
         print("  ✅ PASS: Web domain scan completed successfully.")
    else:
         print(f"  ❌ FAIL: Web domain scan status was: {web_result}")

    return ["Scan engine validation"], []

if __name__ == "__main__":
    _, failed = test_scan_engine()
    sys.exit(len(failed))
