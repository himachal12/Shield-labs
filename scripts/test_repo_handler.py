"""Repository Handler validation script for ShieldLabs."""

import sys
from pathlib import Path
import tempfile
import zipfile
import shutil

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / 'backend'))
sys.path.insert(0, str(ROOT_DIR / 'backend' / 'app'))

from app.utils.repo_handler import validate_github_url, download_github_repo, extract_zip, get_all_code_files, cleanup_temp_repo

def test_repo_handler():
    print("--- REPOSITORY HANDLER TESTS ---")
    passed = []
    failed = []

    # 1. Test validate_github_url
    print("Validating GitHub URL parsing...")
    if validate_github_url("https://github.com/user/repo"):
        print("  ✅ PASS: Valid URL accepted.")
    else:
        print("  ❌ FAIL: Valid URL rejected.")
        failed.append(("validate_github_url", "Valid URL rejected"))

    if not validate_github_url("https://malicious.com/user/repo"):
        print("  ✅ PASS: Invalid URL rejected.")
    else:
        print("  ❌ FAIL: Invalid URL accepted.")
        failed.append(("validate_github_url", "Invalid URL accepted"))

    # 2. Test extract_zip & cleanup
    print("Testing ZIP extraction and discovery...")
    temp_dir = tempfile.mkdtemp()
    try:
        # Create a mock zip file
        zip_path = Path(temp_dir) / "test.zip"
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            zipf.writestr("test.py", "print('hello')")
            zipf.writestr("ignored_folder/test.js", "console.log('ignored')") # folder name does not match IGNORED_DIRS in repo_handler
            zipf.writestr("node_modules/test.js", "console.log('node_modules')") # should be ignored
            
        extracted_path = extract_zip(str(zip_path))
        files = get_all_code_files(extracted_path)
        
        # Verify files list
        has_py = any(f.endswith("test.py") for f in files)
        has_node_modules = any("node_modules" in f for f in files)

        if has_py and not has_node_modules:
            print("  ✅ PASS: ZIP extracted successfully, and only scannable code files returned.")
        else:
            print(f"  ❌ FAIL: File discovery failed. files: {files}")
            failed.append(("ZIP extraction discovery", ""))

        # Verify cleanup
        cleanup_temp_repo(extracted_path)
        if not Path(extracted_path).exists():
             print("  ✅ PASS: Temp folder cleanup verified.")
        else:
             print("  ❌ FAIL: Temp folder not cleaned up.")
             failed.append(("cleanup_temp_repo", ""))

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    # 3. Test invalid/private repository URL exceptions
    print("Testing invalid and private repositories...")
    try:
        download_github_repo("https://github.com/invalid-nonexistent-user/invalid-repo-12345")
        print("  ❌ FAIL: Cloned non-existent repo without error.")
        failed.append(("private/invalid repository handling", "Cloned non-existent repo without error"))
    except RuntimeError as e:
        print("  ✅ PASS: Correctly threw RuntimeError for non-existent/private repo.")
    except Exception as e:
        print(f"  ❌ FAIL: Threw unexpected error: {type(e)} - {e}")
        failed.append(("private/invalid repository handling", str(e)))

    return ["Repository handler validation"], failed

if __name__ == "__main__":
    _, failed = test_repo_handler()
    sys.exit(len(failed))
