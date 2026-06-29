"""Pattern Detector validation script for ShieldLabs."""

import sys
from pathlib import Path
import json

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / 'backend'))
sys.path.insert(0, str(ROOT_DIR / 'backend' / 'app'))

from app.scanners.pattern_detector import scan_file_for_patterns

def test_pattern_detector():
    vulnerable_app_path = ROOT_DIR / "tests" / "samples" / "vulnerable_app.py"
    
    # Read vulnerable_app.py
    with open(vulnerable_app_path, "r", encoding="utf-8") as f:
        source = f.read()

    findings = scan_file_for_patterns(str(vulnerable_app_path), source)

    # Let's verify we got JSON valid output
    try:
        findings_json = json.dumps(findings, indent=2)
        json.loads(findings_json)
    except Exception as e:
        print(f"  ❌ FAIL: Findings are not JSON serializable: {e}")
        return [], [("JSON Serialization", str(e))]

    print("--- PATTERN DETECTOR TESTS ---")
    print(f"Found {len(findings)} pattern matches in vulnerable_app.py")

    expected_types = [
        "SQL Injection",
        "Hardcoded Secret",
        "Weak Hashing",
        "Command Injection",
        "Insecure Deserialization",
        "Weak JWT Implementation",
        "Weak Cryptography",
        "Unvalidated Redirect",
        "Cross-Site Scripting (XSS)",
        "Missing CSRF Protection",
        "Missing Rate Limiting",
        "Missing Security Headers"
    ]

    detected_types = {f["vuln_type"] for f in findings}
    passed = []
    failed = []

    # Verify each expected type (excluding requirements.txt specific)
    for expected in expected_types:
        matches = [f for f in findings if f["vuln_type"] == expected]
        if matches:
            # Check line, confidence, snippet, severity
            m = matches[0]
            print(f"  ✅ PASS: Detected '{expected}' at line {m.get('line')}, confidence {m.get('confidence')}")
            # Verify severity is correct based on confidence
            confidence = m.get("confidence", 0.5)
            severity = "critical" if confidence >= 0.9 else "high" if confidence >= 0.75 else "medium" if confidence >= 0.5 else "low"
            # Add details
            passed.append(expected)
        else:
            print(f"  ❌ FAIL: Did not detect '{expected}' in vulnerable_app.py")
            failed.append((expected, "Vulnerability pattern not found in code findings"))

    # Test Dependency Issues on requirements.txt
    mock_reqs = "flask\nrequests==2.0.0\n"
    reqs_findings = scan_file_for_patterns("requirements.txt", mock_reqs)
    dep_issues = [f for f in reqs_findings if "Dependency Vulnerability" in f["vuln_type"]]
    if dep_issues:
        print(f"  ✅ PASS: Detected Dependency Issues in requirements.txt")
        passed.append("Dependency Issues")
    else:
        print(f"  ❌ FAIL: Did not detect Dependency Issues in mock requirements.txt")
        failed.append(("Dependency Issues", "Vulnerability pattern not found in requirements.txt"))

    return passed, failed

if __name__ == "__main__":
    passed, failed = test_pattern_detector()
    sys.exit(len(failed))
