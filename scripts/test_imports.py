"""Import validation script for ShieldLabs."""

import sys
from pathlib import Path

# Add backend and app paths
ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / 'backend'))
sys.path.insert(0, str(ROOT_DIR / 'backend' / 'app'))

def test_imports():
    modules = [
        ("scanners.semantic_analyzer", ["review_finding", "filter_findings_with_llm"]),
        ("scanners.pattern_detector", ["scan_file_for_patterns"]),
        ("scanners.fix_generator", ["generate_fix", "generate_fixes_for_all"]),
        ("agents.code_parser", ["CodeParserAgent"]),
        ("agents.fix_generation", ["FixGenerationAgent"]),
        ("utils.repo_handler", ["download_github_repo", "extract_zip", "get_all_code_files"]),
        ("utils.llm", ["ask_llm", "analyze_code_security"]),
        ("scan_engine", ["scan_local_file", "scan_github_repo"])
    ]

    passed = []
    failed = []

    print("--- IMPORT VALIDATION ---")
    for mod_name, symbols in modules:
        try:
            # Dynamically import
            mod = __import__(mod_name, fromlist=symbols)
            # Verify symbols exist
            for sym in symbols:
                assert hasattr(mod, sym), f"Symbol '{sym}' not found in {mod_name}"
            print(f"  ✅ PASS: Imported '{mod_name}' successfully.")
            passed.append(mod_name)
        except Exception as e:
            print(f"  ❌ FAIL: Failed to import '{mod_name}'. Error: {e}")
            failed.append((mod_name, str(e)))

    return passed, failed

if __name__ == "__main__":
    passed, failed = test_imports()
    sys.exit(len(failed))
