"""AST Parser validation script for ShieldLabs."""

import sys
from pathlib import Path
import tempfile
import shutil

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / 'backend'))
sys.path.insert(0, str(ROOT_DIR / 'backend' / 'app'))

from app.scanners.ast_parser import parse_file

def test_ast_parser():
    print("--- AST PARSER TESTS ---")
    
    # 1. Prepare temp directory for mock files
    temp_dir = tempfile.mkdtemp()
    passed = []
    failed = []

    try:
        # --- PYTHON PARSING TEST ---
        py_code = """
import os
import sys

class DatabaseManager:
    def __init__(self, db_url):
        self.db_url = db_url

    def run_query(self, sql):
        db.execute(sql)

def authenticate_user(username, password):
    # login logic
    requests.post("https://auth.com/login")
    return True
"""
        py_file = Path(temp_dir) / "test.py"
        with open(py_file, "w", encoding="utf-8") as f:
            f.write(py_code)

        py_res = parse_file(str(py_file))
        if py_res:
            print("  ✅ PASS: Python file parsed successfully.")
            # Verify functions, classes, imports, db queries, api calls, auth logic
            if any(f["name"] == "run_query" for f in py_res["functions"]):
                print("    ✅ PASS: Extracted Python functions.")
            else:
                print("    ❌ FAIL: Could not extract Python function 'run_query'.")
                failed.append(("Python function extraction", ""))

            if any(c["name"] == "DatabaseManager" for c in py_res.get("classes", [])):
                print("    ✅ PASS: Extracted Python classes.")
            else:
                print("    ❌ FAIL: Could not extract Python class 'DatabaseManager'.")
                failed.append(("Python class extraction", ""))

            if "os" in py_res["imports"]:
                print("    ✅ PASS: Extracted Python imports.")
            else:
                print("    ❌ FAIL: Could not extract Python imports.")
                failed.append(("Python imports extraction", ""))
        else:
            print("  ❌ FAIL: Python parsing returned None.")
            failed.append(("Python AST parsing", ""))

        # --- JAVASCRIPT PARSING TEST ---
        js_code = """
import { Axios } from 'axios';

class ApiClient {
    constructor() {
        this.client = new Axios();
    }
}

async function loginUser(email, password) {
    const res = await fetch('/api/login');
    return res.json();
}
"""
        js_file = Path(temp_dir) / "test.js"
        with open(js_file, "w", encoding="utf-8") as f:
            f.write(js_code)

        js_res = parse_file(str(js_file))
        if js_res:
            print("  ✅ PASS: JavaScript file parsed successfully.")
            if any(f["name"] == "loginUser" for f in js_res["functions"]):
                print("    ✅ PASS: Extracted JavaScript functions.")
            else:
                print("    ❌ FAIL: Could not extract JS function 'loginUser'.")
                failed.append(("JavaScript function extraction", ""))

            if any(c["name"] == "ApiClient" for c in js_res.get("classes", [])):
                print("    ✅ PASS: Extracted JavaScript classes.")
            else:
                print("    ❌ FAIL: Could not extract JS class 'ApiClient'.")
                failed.append(("JavaScript class extraction", ""))
        else:
            print("  ❌ FAIL: JavaScript parsing returned None.")
            failed.append(("JavaScript AST parsing", ""))

        # --- GO PARSING TEST ---
        go_code = """
package main

import (
    "database/sql"
    "fmt"
)

type DbConnection struct {
    Host string
}

func ConnectDb() {
    sql.Open("postgres", "connstr")
}
"""
        go_file = Path(temp_dir) / "test.go"
        with open(go_file, "w", encoding="utf-8") as f:
            f.write(go_code)

        go_res = parse_file(str(go_file))
        if go_res:
            print("  ✅ PASS: Go file parsed successfully.")
            if any(f["name"] == "ConnectDb" for f in go_res["functions"]):
                print("    ✅ PASS: Extracted Go functions.")
            else:
                print("    ❌ FAIL: Could not extract Go function 'ConnectDb'.")
                failed.append(("Go function extraction", ""))

            if any(c["name"] == "DbConnection" for c in go_res.get("classes", [])):
                print("    ✅ PASS: Extracted Go classes (structs).")
            else:
                print("    ❌ FAIL: Could not extract Go class (struct) 'DbConnection'.")
                failed.append(("Go struct extraction", ""))
        else:
            print("  ❌ FAIL: Go parsing returned None.")
            failed.append(("Go AST parsing", ""))

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return ["AST parsing validation"], failed

if __name__ == "__main__":
    _, failed = test_ast_parser()
    sys.exit(len(failed))
