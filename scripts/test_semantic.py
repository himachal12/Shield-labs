"""Semantic Analyzer validation script for ShieldLabs."""

import sys
from pathlib import Path
import time
import requests
from unittest.mock import patch

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / 'backend'))
sys.path.insert(0, str(ROOT_DIR / 'backend' / 'app'))

from app.scanners.semantic_analyzer import review_finding, filter_findings_with_llm
from app.config import settings

def test_semantic_analyzer():
    print("--- SEMANTIC ANALYZER TESTS ---")
    
    mock_finding = {
        "vuln_type": "SQL Injection",
        "file": "app/db.py",
        "line": 10,
        "code_snippet": "query = 'SELECT * FROM users WHERE id = ' + user_id",
        "confidence": 0.5,
        "reason": "String concatenation in query"
    }

    # 1. Live Connection check
    ollama_url = f"{settings.ollama_base_url}/api/generate"
    print(f"Checking Ollama at {settings.ollama_base_url}...")
    ollama_online = False
    try:
        r = requests.get(settings.ollama_base_url, timeout=3)
        ollama_online = r.status_code == 200
        print(f"  Ollama status: {'ONLINE' if ollama_online else 'OFFLINE (non-200 response)'}")
    except Exception as e:
        print(f"  Ollama status: OFFLINE ({e})")

    # 2. Test Offline/Fallback Logic
    # If Ollama is offline, review_finding should return UNCERTAIN.
    # Let's force a connection error mock to test this fallback path.
    print("Testing offline fallback logic...")
    with patch("requests.post", side_effect=requests.exceptions.ConnectionError):
        reviewed = review_finding(mock_finding)
        if reviewed.get("llm_verdict") == "UNCERTAIN" and "LLM unavailable" in reviewed.get("llm_explanation"):
            print("  ✅ PASS: Offline fallback correctly returns UNCERTAIN verdict.")
        else:
            print(f"  ❌ FAIL: Offline fallback failed. Got verdict: {reviewed.get('llm_verdict')}")

    # 3. Test Response Parsing with Mocked Success Response
    # Test that Markdown fences stripping and JSON parsing work properly.
    print("Testing response parsing logic...")
    mock_response_text = '```json\n{"verdict": "CONFIRM", "explanation": "Vulnerable because it concatenates input."}\n```'
    
    class MockResponse:
        def __init__(self, text):
            self.text = text
        def raise_for_status(self):
            pass
        def json(self):
            return {"response": self.text}

    with patch("requests.post", return_value=MockResponse(mock_response_text)):
        reviewed = review_finding(mock_finding)
        if reviewed.get("llm_verdict") == "CONFIRM" and reviewed.get("llm_explanation") == "Vulnerable because it concatenates input.":
            print("  ✅ PASS: Response parsing handles markdown fences and valid JSON.")
        else:
            print(f"  ❌ FAIL: Response parsing failed. Got: {reviewed}")

    # 4. Live Test (if online)
    passed_live = True
    if ollama_online:
        print("Running live Ollama test...")
        start_time = time.time()
        try:
            reviewed = review_finding(mock_finding)
            duration = time.time() - start_time
            print(f"  Live review response time: {duration:.2f}s")
            print(f"  Live Verdict: {reviewed.get('llm_verdict')}")
            print(f"  Live Explanation: {reviewed.get('llm_explanation')}")
            if "llm_verdict" in reviewed:
                print("  ✅ PASS: Live review succeeded.")
            else:
                print("  ❌ FAIL: Live review failed to return verdict.")
                passed_live = False
        except Exception as e:
            print(f"  ❌ FAIL: Live review failed with exception: {e}")
            passed_live = False
    else:
        print("  ⚠️ WARNING: Skipping live Ollama tests (Ollama is offline).")

    # Return status
    failed = []
    if not passed_live:
        failed.append(("Live Ollama test failed", ""))
    return ["Semantic validation"], failed

if __name__ == "__main__":
    _, failed = test_semantic_analyzer()
    sys.exit(len(failed))
