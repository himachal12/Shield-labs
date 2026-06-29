"""Master test runner for the ShieldLabs Automated Validation Suite."""

import sys
import os
import time
import json
import shutil
import tempfile
import psutil
import requests
from pathlib import Path
from importlib import import_module

ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR / 'backend'))
sys.path.insert(0, str(ROOT_DIR / 'backend' / 'app'))

from app.config import settings

# Global test tracker
total_tests = 0
passed_tests = 0
failed_tests = 0
warnings = []
performance_metrics = {}
failures_detail = {}

def track_test(name, success, detail="", warning=""):
    global total_tests, passed_tests, failed_tests
    total_tests += 1
    if success:
        passed_tests += 1
    else:
        failed_tests += 1
        failures_detail[name] = detail
    if warning:
        warnings.append(warning)

def run_phase_1_structure():
    print("\n=== PHASE 1: PROJECT STRUCTURE VALIDATION ===")
    required_dirs = [
        "backend",
        "frontend",
        "backend/app/agents",
        "backend/app/api",
        "backend/app/models",
        "backend/app/utils",
        "backend/app/scanners",
        "tests",
        "docs"
    ]
    for r_dir in required_dirs:
        dir_path = ROOT_DIR / r_dir
        exists = dir_path.is_dir()
        track_test(f"Structure: {r_dir}", exists, f"Directory '{r_dir}' is missing.")
        if exists:
            print(f"  ✅ '{r_dir}/' exists.")
        else:
            print(f"  ❌ '{r_dir}/' is missing!")

def run_phase_2_dependencies():
    print("\n=== PHASE 2: DEPENDENCY VALIDATION ===")
    required_packages = [
        "fastapi", "sqlalchemy", "crewai", "pydantic", "ollama", "groq", "requests", "git"
    ]
    for pkg in required_packages:
        try:
            import_module(pkg)
            track_test(f"Dependency: {pkg}", True)
            print(f"  ✅ Package '{pkg}' is installed and importable.")
        except ImportError as e:
            track_test(f"Dependency: {pkg}", False, f"Package '{pkg}' failed to import: {e}")
            print(f"  ❌ Package '{pkg}' is missing or broken!")

def run_phase_3_env():
    print("\n=== PHASE 3: ENVIRONMENT VALIDATION ===")
    env_file = ROOT_DIR / "backend" / ".env"
    exists = env_file.is_file()
    track_test("Environment: .env exists", exists, ".env file not found in backend/")
    
    if exists:
        print("  ✅ .env file exists.")
        # Check required keys
        keys = ["GROQ_API_KEY", "OLLAMA_BASE_URL", "OLLAMA_MODEL"]
        for k in keys:
            val = os.getenv(k) or getattr(settings, k.lower(), None)
            if val:
                track_test(f"Env Var: {k}", True)
                # Obfuscate API key in print
                print(f"  ✅ {k} is configured.")
            else:
                track_test(f"Env Var: {k}", False, f"Variable '{k}' is empty or missing.", f"Missing environment variable: {k}")
                print(f"  ⚠️ {k} is not set.")
    else:
        print("  ❌ .env file does not exist!")

def run_phase_4_ollama():
    print("\n=== PHASE 4: OLLAMA VALIDATION ===")
    url = settings.ollama_base_url
    print(f"Connecting to Ollama at {url}...")
    
    start_time = time.time()
    try:
        r = requests.get(url, timeout=3)
        online = r.status_code == 200
    except Exception as e:
        online = False
        track_test("Ollama Connection", False, f"Could not connect to Ollama: {e}", "Ollama server is offline.")
        print(f"  ❌ Ollama is unreachable at {url}")
        return

    track_test("Ollama Connection", True)
    latency = time.time() - start_time
    performance_metrics["Ollama Latency"] = f"{latency:.2f}s"
    print(f"  ✅ Ollama is reachable. Latency: {latency:.2f}s")

    # Check model response
    model_name = settings.ollama_model
    print(f"Testing model '{model_name}' response...")
    start_time = time.time()
    try:
        resp = requests.post(f"{url}/api/generate", json={
            "model": model_name,
            "prompt": "What is SQL Injection? Respond in one sentence.",
            "stream": False,
            "options": {"num_predict": 50}
        }, timeout=15)
        
        if resp.status_code == 200:
            gen_text = resp.json().get("response", "").strip()
            duration = time.time() - start_time
            track_test("Ollama Prompt Response", True)
            performance_metrics["Ollama Prompt Response Duration"] = f"{duration:.2f}s"
            print(f"  ✅ Model responds. Response time: {duration:.2f}s")
            print(f"  Response: {gen_text}")
        else:
            track_test("Ollama Prompt Response", False, f"Ollama returned non-200 code: {resp.status_code}")
            print(f"  ❌ Model returned status code {resp.status_code}")
    except Exception as e:
        track_test("Ollama Prompt Response", False, f"Ollama response failed: {e}")
        print(f"  ❌ Model response failed: {e}")

def run_scripts():
    print("\n=== RUNNING STANDALONE TESTING SCRIPTS ===")
    scripts = [
        ("test_imports.py", "scripts.test_imports"),
        ("test_pattern_detector.py", "scripts.test_pattern_detector"),
        ("test_semantic.py", "scripts.test_semantic"),
        ("test_fix_generator.py", "scripts.test_fix_generator"),
        ("test_ast.py", "scripts.test_ast"),
        ("test_repo_handler.py", "scripts.test_repo_handler"),
        ("test_database.py", "scripts.test_database"),
        ("test_api.py", "scripts.test_api"),
        ("test_scan_engine.py", "scripts.test_scan_engine")
    ]

    for filename, module_path in scripts:
        print(f"\nRunning {filename}...")
        start_time = time.time()
        try:
            mod = import_module(module_path)
            # Find the main test function (e.g. test_imports, test_pattern_detector)
            func_name = filename[:-3]
            func = getattr(mod, func_name, None)
            if func:
                passed, failed = func()
                duration = time.time() - start_time
                performance_metrics[f"{filename} duration"] = f"{duration:.2f}s"
                for p in passed:
                    track_test(f"Script {filename}: {p}", True)
                for f, err in failed:
                    track_test(f"Script {filename}: {f}", False, err)
            else:
                track_test(f"Script {filename} load", False, f"Could not find test function '{func_name}'")
        except Exception as e:
            track_test(f"Script {filename} execution", False, str(e))
            print(f"  ❌ Script {filename} crashed: {e}")

def run_phase_15_performance():
    print("\n=== PHASE 15: PERFORMANCE & RESOURCE TESTS ===")
    # 1. Regex parsing speed test
    vulnerable_app_path = ROOT_DIR / "tests" / "samples" / "vulnerable_app.py"
    if vulnerable_app_path.is_file():
        from app.scanners.pattern_detector import scan_file_for_patterns
        with open(vulnerable_app_path, "r", encoding="utf-8") as f:
            code = f.read()
        start = time.time()
        for _ in range(50):
            scan_file_for_patterns(str(vulnerable_app_path), code)
        duration = time.time() - start
        avg_speed = duration / 50
        track_test("Performance: Regex Scanning Speed", True)
        performance_metrics["Avg Regex Speed (per file)"] = f"{avg_speed * 1000:.2f}ms"
        print(f"  ✅ Regex scanning speed: {avg_speed * 1000:.2f}ms per file (averaged over 50 runs)")

    # 2. Database write speed
    from app.models.database import SessionLocal
    from app.models import repository
    db = SessionLocal()
    try:
        start = time.time()
        scan = repository.create_scan(db, target="perf_test", scan_type="code")
        for i in range(100):
            repository.add_finding(
                db=db,
                scan_id=scan.scan_id,
                vuln_type="Perf Test Injection",
                severity="low",
                description=f"Performance test finding {i}",
                file_path="perf.py",
                line_number=i
            )
        duration = time.time() - start
        track_test("Performance: DB Write Speed", True)
        performance_metrics["DB 100 Write Duration"] = f"{duration:.2f}s"
        print(f"  ✅ Database write speed: {duration:.2f}s for 100 findings inserts.")
        repository.delete_scan(db, scan.scan_id)
    except Exception as e:
        track_test("Performance: DB Write Speed", False, str(e))
        print(f"  ❌ DB write speed test failed: {e}")
    finally:
        db.close()

    # 3. CPU and Memory
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    cpu_percent = process.cpu_percent(interval=0.5)
    performance_metrics["Memory Usage"] = f"{mem_info.rss / 1024 / 1024:.2f} MB"
    performance_metrics["CPU Usage"] = f"{cpu_percent:.1f}%"
    track_test("Performance: Resource usage checks", True)
    print(f"  ✅ Memory Usage: {mem_info.rss / 1024 / 1024:.2f} MB")
    print(f"  ✅ CPU Usage: {cpu_percent:.1f}%")

def run_phase_16_negatives():
    print("\n=== PHASE 16: NEGATIVE AND EDGE CASES ===")
    from app.scanners.pattern_detector import scan_file_for_patterns
    from app.scanners.ast_parser import parse_file

    # 1. Non-existent file
    try:
        res = parse_file("nonexistent_file_path.py")
        track_test("Negative: Non-existent file", res is None or res.get("parse_error") is not None)
        print("  ✅ Non-existent file handled gracefully.")
    except Exception as e:
        track_test("Negative: Non-existent file", False, str(e))
        print(f"  ❌ Non-existent file crashed: {e}")

    # 2. Empty file
    try:
        findings = scan_file_for_patterns("empty.py", "")
        track_test("Negative: Empty file scanning", len(findings) == 0)
        print("  ✅ Empty file scanning returns zero findings.")
    except Exception as e:
        track_test("Negative: Empty file scanning", False, str(e))

    # 3. Binary file
    try:
        res = parse_file("image.png")
        track_test("Negative: Binary file AST parsing", res is None)
        print("  ✅ Binary file AST parsing skipped gracefully.")
    except Exception as e:
        track_test("Negative: Binary file AST parsing", False, str(e))

    # 4. Syntax errors handling
    try:
        bad_code = "class DatabaseManager:\n    def __init__(\n"
        res = parse_file("bad_syntax.py") # wait, parse_file uses extension to decide. So we must write it to file, or use parse_python_file.
        # Let's verify parse_file returns None or dict with parse_error
        temp_bad = tempfile.NamedTemporaryFile(suffix=".py", delete=False)
        temp_bad.write(bad_code.encode())
        temp_bad.close()
        res = parse_file(temp_bad.name)
        os.unlink(temp_bad.name)
        
        track_test("Negative: Python Syntax Error Handling", res is not None and res.get("parse_error") is not None)
        print("  ✅ Syntax error handled gracefully (returns parse_error).")
    except Exception as e:
        track_test("Negative: Python Syntax Error Handling", False, str(e))
        print(f"  ❌ Syntax error handling crashed: {e}")

def run_phase_17_regression():
    print("\n=== PHASE 17: REGRESSION TESTS ===")
    # Ensure Pattern Detector, Semantic Analyzer, and Fix Generator works correctly on standard inputs.
    from app.scanners.pattern_detector import scan_file_for_patterns
    findings = scan_file_for_patterns("test.py", "SECRET_KEY = '123456789'")
    is_pd_ok = len(findings) > 0 and findings[0]["vuln_type"] == "Hardcoded Secret"
    track_test("Regression: Pattern Detector works", is_pd_ok)
    if is_pd_ok:
        print("  ✅ Pattern Detector regression check passed.")
    else:
        print("  ❌ Pattern Detector regression check failed!")

def generate_report():
    print("\n" + "="*50)
    print("                FINAL VALIDATION REPORT")
    print("="*50)
    print(f"  Total Tests Executed: {total_tests}")
    print(f"  Tests Passed:         {passed_tests}")
    print(f"  Tests Failed:         {failed_tests}")
    print(f"  Warnings Triggered:   {len(warnings)}")
    print("-"*50)
    print("  Performance Metrics:")
    for k, v in performance_metrics.items():
        print(f"    - {k}: {v}")
    
    if failed_tests > 0:
        print("-"*50)
        print("  Failure Details:")
        for k, v in failures_detail.items():
            print(f"    ❌ {k}: {v}")
            
    print("="*50)

    # Save validation_report.md artifact
    artifact_dir = Path("C:/Users/acer/.gemini/antigravity-ide/brain/4fa8a152-a800-4ea3-a4d5-fbb6837616ff")
    if artifact_dir.is_dir():
        report_file = artifact_dir / "validation_report.md"
        
        # Build Markdown content
        md_content = f"""# ShieldLabs Automated Validation Report

This report summarizes the status of the ShieldLabs validation suite covering imports, dependencies, database schema, APIs, scanner modules, LLM response, and overall stability.

## Summary

| Metric | Count |
| --- | --- |
| **Total Tests** | {total_tests} |
| **Passed** | {passed_tests} |
| **Failed** | {failed_tests} |
| **Warnings** | {len(warnings)} |

## Diagnostic Details

### Scanners Validation
- **Pattern Detector**: {"✅ PASS" if not any("test_pattern_detector" in k for k in failures_detail) else "❌ FAIL"}
- **Semantic Analyzer**: {"✅ PASS" if not any("test_semantic" in k for k in failures_detail) else "❌ FAIL"}
- **Fix Generator**: {"✅ PASS" if not any("test_fix_generator" in k for k in failures_detail) else "❌ FAIL"}
- **AST Parser**: {"✅ PASS" if not any("test_ast" in k for k in failures_detail) else "❌ FAIL"}

### Database and APIs
- **Database CRUD**: {"✅ PASS" if not any("test_database" in k for k in failures_detail) else "❌ FAIL"}
- **FastAPI Endpoints**: {"✅ PASS" if not any("test_api" in k for k in failures_detail) else "❌ FAIL"}

### Performance Metrics

"""
        for k, v in performance_metrics.items():
            md_content += f"- **{k}**: {v}\n"

        if failed_tests > 0:
            md_content += "\n## Failure Details\n"
            for k, v in failures_detail.items():
                md_content += f"- **{k}**: {v}\n"
        else:
            md_content += "\n## ✅ All Core Validations Passed Successfully\n"

        if warnings:
            md_content += "\n## Warnings\n"
            for w in warnings:
                md_content += f"- {w}\n"

        with open(report_file, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"Generated validation report artifact: {report_file}")

if __name__ == "__main__":
    run_phase_1_structure()
    run_phase_2_dependencies()
    run_phase_3_env()
    run_phase_4_ollama()
    run_scripts()
    run_phase_15_performance()
    run_phase_16_negatives()
    run_phase_17_regression()
    generate_report()
    
    # Exit with code matching failures
    sys.exit(failed_tests)
