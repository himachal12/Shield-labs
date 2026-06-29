"""Fix Generator validation script for ShieldLabs."""

import sys
from pathlib import Path
import time
import requests
from unittest.mock import patch

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / 'backend'))
sys.path.insert(0, str(ROOT_DIR / 'backend' / 'app'))

from app.scanners.fix_generator import generate_fix, generate_fixes_for_all
from app.config import settings

def test_fix_generator():
    print("--- FIX GENERATOR TESTS ---")
    
    mock_finding = {
        "vuln_type": "SQL Injection",
        "file": "app/db.py",
        "line": 10,
        "code_snippet": "query = 'SELECT * FROM users WHERE id = ' + user_id",
        "confidence": 0.5,
        "reason": "String concatenation in query"
    }

    # 1. Live Connection check
    print(f"Checking Ollama at {settings.ollama_base_url}...")
    ollama_online = False
    try:
        r = requests.get(settings.ollama_base_url, timeout=3)
        ollama_online = r.status_code == 200
        print(f"  Ollama status: {'ONLINE' if ollama_online else 'OFFLINE'}")
    except Exception as e:
        print(f"  Ollama status: OFFLINE ({e})")

    # 2. Test Offline/Fallback Logic
    print("Testing offline fallback logic...")
    with patch("requests.post", side_effect=requests.exceptions.ConnectionError):
        fixed = generate_fix(mock_finding)
        if "fix_code" in fixed and "fix_explanation" in fixed:
            # Should have code like '# Ollama unavailable'
            if "unavailable" in fixed["fix_code"] or "manual" in fixed["fix_code"].lower():
                print("  ✅ PASS: Offline fallback correctly populates fallback code.")
            else:
                print(f"  ❌ FAIL: Offline fallback code unexpected: {fixed['fix_code']}")
        else:
            print(f"  ❌ FAIL: Offline fallback failed. Missing keys. Got: {fixed}")

    # 3. Test Response Parsing with Mocked Success Response
    print("Testing response parsing logic...")
    mock_response_text = '```json\n{"fixed_code": "db.execute(\'SELECT * FROM users WHERE id = :id\', {\'id\': user_id})", "fix_explanation": "Use parameterized query."}\n```'
    
    class MockResponse:
        def __init__(self, text):
            self.text = text
        def raise_for_status(self):
            pass
        def json(self):
            return {"response": self.text}

    with patch("requests.post", return_value=MockResponse(mock_response_text)):
        fixed = generate_fix(mock_finding)
        if fixed.get("fix_code") == "db.execute('SELECT * FROM users WHERE id = :id', {'id': user_id})" and fixed.get("fix_explanation") == "Use parameterized query.":
            print("  ✅ PASS: Response parsing handles markdown fences and valid JSON.")
        else:
            print(f"  ❌ FAIL: Response parsing failed. Got: {fixed}")

    # 4. Live Test (if online)
    passed_live = True
    if ollama_online:
        print("Running live Ollama fix generation test...")
        start_time = time.time()
        try:
            fixed = generate_fix(mock_finding)
            duration = time.time() - start_time
            print(f"  Live fix response time: {duration:.2f}s")
            print(f"  Live Fix Code:\n{fixed.get('fix_code')}")
            print(f"  Live Explanation: {fixed.get('fix_explanation')}")
            if "fix_code" in fixed and fixed.get("fix_code"):
                print("  ✅ PASS: Live fix generation succeeded.")
            else:
                print("  ❌ FAIL: Live fix generation returned empty fix code.")
                passed_live = False
        except Exception as e:
            print(f"  ❌ FAIL: Live fix generation failed with exception: {e}")
            passed_live = False
    else:
        print("  ⚠️ WARNING: Skipping live Ollama tests (Ollama is offline).")

    # Return status
    failed = []
    if not passed_live:
        failed.append(("Live Ollama fix generation failed", ""))
    return ["Fix generator validation"], failed

if __name__ == "__main__":
    _, failed = test_fix_generator()
    sys.exit(len(failed))
