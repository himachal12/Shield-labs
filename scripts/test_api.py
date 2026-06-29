"""FastAPI routes validation script for ShieldLabs."""

import sys
from pathlib import Path
from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / 'backend'))
sys.path.insert(0, str(ROOT_DIR / 'backend' / 'app'))

from app.main import app

def test_api():
    print("--- FASTAPI ENDPOINT TESTS ---")
    client = TestClient(app)
    passed = []
    failed = []

    # 1. GET /api/health
    try:
        r = client.get("/api/health")
        if r.status_code == 200 and r.json().get("status") == "ok":
            print("  ✅ PASS: GET /api/health returned 200 OK.")
            passed.append("GET /api/health")
        else:
            print(f"  ❌ FAIL: GET /api/health failed. Code: {r.status_code}, Body: {r.text}")
            failed.append(("GET /api/health", f"Status: {r.status_code}"))
    except Exception as e:
         print(f"  ❌ FAIL: GET /api/health failed with exception: {e}")
         failed.append(("GET /api/health", str(e)))

    # 2. POST /api/scan/code (queued scan creation)
    # Target can be a local zip_path or repo_url
    try:
        payload = {"zip_path": "tests/samples/vulnerable_app.py"}
        r = client.post("/api/scan/code", json=payload)
        if r.status_code == 201 and "scan_id" in r.json():
            print("  ✅ PASS: POST /api/scan/code returned 201 Queued.")
            passed.append("POST /api/scan/code")
            scan_id = r.json()["scan_id"]
        else:
            print(f"  ❌ FAIL: POST /api/scan/code failed. Code: {r.status_code}, Body: {r.text}")
            failed.append(("POST /api/scan/code", f"Status: {r.status_code}"))
            scan_id = None
    except Exception as e:
         print(f"  ❌ FAIL: POST /api/scan/code failed with exception: {e}")
         failed.append(("POST /api/scan/code", str(e)))
         scan_id = None

    # 3. POST /api/analyze (start agent analysis)
    if scan_id:
        try:
            r = client.post("/api/analyze", json={"scan_id": scan_id})
            if r.status_code == 200 and r.json().get("scan_id") == scan_id:
                print("  ✅ PASS: POST /api/analyze returned 200 Success.")
                passed.append("POST /api/analyze")
            else:
                print(f"  ❌ FAIL: POST /api/analyze failed. Code: {r.status_code}, Body: {r.text}")
                failed.append(("POST /api/analyze", f"Status: {r.status_code}"))
        except Exception as e:
             print(f"  ❌ FAIL: POST /api/analyze failed with exception: {e}")
             failed.append(("POST /api/analyze", str(e)))

    # 4. GET /api/results/{id}
    if scan_id:
        try:
            r = client.get(f"/api/results/{scan_id}")
            if r.status_code == 200 and r.json().get("scan_id") == scan_id:
                print("  ✅ PASS: GET /api/results/{id} returned 200 OK.")
                passed.append("GET /api/results/{id}")
            else:
                print(f"  ❌ FAIL: GET /api/results/{id} failed. Code: {r.status_code}, Body: {r.text}")
                failed.append(("GET /api/results/{id}", f"Status: {r.status_code}"))
        except Exception as e:
             print(f"  ❌ FAIL: GET /api/results/{id} failed with exception: {e}")
             failed.append(("GET /api/results/{id}", str(e)))

    # 5. Error handling: GET non-existent scan
    try:
        r = client.get("/api/results/nonexistent_scan_123")
        if r.status_code == 404:
            print("  ✅ PASS: Correctly returned 404 for non-existent scan.")
            passed.append("Error handling 404")
        else:
            print(f"  ❌ FAIL: GET nonexistent scan returned code: {r.status_code}")
            failed.append(("Error handling 404", f"Expected 404, got {r.status_code}"))
    except Exception as e:
         print(f"  ❌ FAIL: GET nonexistent scan failed with exception: {e}")
         failed.append(("Error handling 404", str(e)))

    return passed, failed

if __name__ == "__main__":
    passed, failed = test_api()
    sys.exit(len(failed))
