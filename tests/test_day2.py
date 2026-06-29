"""
test_day2.py

Automated test script for Day 2.
Run this to verify everything works before merging with Day 1.
"""

import requests
import json

BASE_URL = "http://localhost:8000/api/v1"
passed = 0
failed = 0


def check(test_name: str, condition: bool, details: str = ""):
    """Helper to print pass/fail for each test."""
    global passed, failed
    if condition:
        print(f"  ✅ PASS: {test_name}")
        passed += 1
    else:
        print(f"  ❌ FAIL: {test_name} {details}")
        failed += 1


def run_tests():
    global passed, failed

    print("\n" + "="*50)
    print("  SHIELDLABS DAY 2 — AUTOMATED TEST SUITE")
    print("="*50)

    # ── TEST 1: Root ──
    print("\n[1] Root Endpoint")
    r = requests.get("http://localhost:8000/")
    check("Status 200", r.status_code == 200)
    check("Has name field", "name" in r.json())
    check("App name correct", r.json()["name"] == "ShieldLabs")

    # ── TEST 2: Health ──
    print("\n[2] Health Check")
    r = requests.get(f"{BASE_URL}/scans/health")
    check("Status 200", r.status_code == 200)
    check("Success true", r.json()["success"] is True)

    # ── TEST 3: Create Scan ──
    print("\n[3] Create Scan")
    payload = {"target": "github.com/test/autoscan", "scan_type": "code"}
    r = requests.post(f"{BASE_URL}/scans/", json=payload)
    check("Status 201", r.status_code == 201)
    scan = r.json()
    check("Has ID", "id" in scan)
    check("Status is pending", scan["status"] == "pending")
    check("Target matches", scan["target"] == "github.com/test/autoscan")
    scan_id = scan["id"]

    # ── TEST 4: Get All Scans ──
    print("\n[4] Get All Scans")
    r = requests.get(f"{BASE_URL}/scans/")
    check("Status 200", r.status_code == 200)
    check("Returns list", isinstance(r.json(), list))
    check("At least 1 scan", len(r.json()) >= 1)

    # ── TEST 5: Get Scan By ID ──
    print("\n[5] Get Scan By ID")
    r = requests.get(f"{BASE_URL}/scans/{scan_id}")
    check("Status 200", r.status_code == 200)
    check("ID matches", r.json()["id"] == scan_id)
    check("Has findings list", "findings" in r.json())

    # ── TEST 6: 404 Handling ──
    print("\n[6] 404 Handling")
    r = requests.get(f"{BASE_URL}/scans/99999")
    check("Status 404", r.status_code == 404)
    check("Has detail message", "detail" in r.json())

    # ── TEST 7: Validation Error ──
    print("\n[7] Pydantic Validation")
    bad_payload = {"target": "x", "scan_type": "invalid_type"}
    r = requests.post(f"{BASE_URL}/scans/", json=bad_payload)
    check("Status 422 on bad data", r.status_code == 422)

    # ── TEST 8: Add Findings ──
    print("\n[8] Add Findings")
    finding1 = {
        "vuln_type": "SQL Injection",
        "severity": "critical",
        "description": "Raw SQL query built from user input",
        "file_path": "app/db.py",
        "line_number": 42
    }
    r = requests.post(f"{BASE_URL}/scans/{scan_id}/findings", json=finding1)
    check("Status 201", r.status_code == 201)
    check("vuln_type correct", r.json()["vuln_type"] == "SQL Injection")
    check("severity correct", r.json()["severity"] == "critical")

    finding2 = {
        "vuln_type": "XSS",
        "severity": "high",
        "description": "User input rendered without sanitization",
        "file_path": "app/views.py",
        "line_number": 88
    }
    r = requests.post(f"{BASE_URL}/scans/{scan_id}/findings", json=finding2)
    check("Second finding created", r.status_code == 201)

    # ── TEST 9: Get Findings ──
    print("\n[9] Get Findings")
    r = requests.get(f"{BASE_URL}/scans/{scan_id}/findings")
    check("Status 200", r.status_code == 200)
    check("Returns 2 findings", len(r.json()) == 2)
    check("Critical finding first", r.json()[0]["severity"] == "critical")

    # ── TEST 10: Filter Findings ──
    print("\n[10] Filter Findings by Severity")
    r = requests.get(f"{BASE_URL}/scans/{scan_id}/findings?severity=critical")
    check("Status 200", r.status_code == 200)
    check("Only 1 result", len(r.json()) == 1)
    check("Is critical", r.json()[0]["severity"] == "critical")

    # ── TEST 11: Scan Has Updated Count ──
    print("\n[11] Scan Findings Count Updated")
    r = requests.get(f"{BASE_URL}/scans/{scan_id}")
    check("total_findings is 2", r.json()["total_findings"] == 2)

    # ── TEST 12: AI Endpoint ──
    print("\n[12] AI Integration")
    ai_payload = {
        "prompt": "In one sentence, what is XSS?",
        "prefer_local": False
    }
    r = requests.post(f"{BASE_URL}/scans/ai/ask", json=ai_payload)
    check("Status 200", r.status_code == 200)
    check("Success true", r.json()["success"] is True)
    check("Has response", r.json()["response"] is not None)
    check("Has model_used", r.json()["model_used"] is not None)

    # ── TEST 13: Delete Scan ──
    print("\n[13] Delete Scan")
    r = requests.delete(f"{BASE_URL}/scans/{scan_id}")
    check("Status 200", r.status_code == 200)
    check("Success message", "deleted" in r.json()["message"].lower())

    # Verify it's gone
    r = requests.get(f"{BASE_URL}/scans/{scan_id}")
    check("Scan is gone (404)", r.status_code == 404)

    # ── RESULTS ──
    print("\n" + "="*50)
    print(f"  RESULTS: {passed} passed, {failed} failed")
    print("="*50)

    if failed == 0:
        print("\n  🎉 ALL TESTS PASSED — Day 2 is complete!")
    else:
        print(f"\n  ⚠️  {failed} tests failed — check the errors above.")


if __name__ == "__main__":
    run_tests()