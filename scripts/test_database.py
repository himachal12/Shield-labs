"""Database validation script for ShieldLabs."""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / 'backend'))
sys.path.insert(0, str(ROOT_DIR / 'backend' / 'app'))

from app.models.database import init_db, SessionLocal
from app.models import repository

def test_database():
    print("--- DATABASE TESTS ---")
    
    # Initialize DB (creates database tables if they do not exist)
    try:
        init_db()
        print("  ✅ PASS: Database initialized successfully.")
    except Exception as e:
        print(f"  ❌ FAIL: Database init failed: {e}")
        return [], [("init_db", str(e))]

    db = SessionLocal()
    passed = []
    failed = []

    try:
        # 1. Create Scan
        scan = repository.create_scan(db, target="test_target", scan_type="code")
        if scan and scan.scan_id:
            print(f"  ✅ PASS: Created scan. scan_id: {scan.scan_id}")
            passed.append("create_scan")
        else:
            print("  ❌ FAIL: Create scan failed.")
            failed.append(("create_scan", "Scan ID not generated"))
            return passed, failed

        scan_id = scan.scan_id

        # 2. Get Scan
        fetched_scan = repository.get_scan(db, scan_id)
        if fetched_scan and fetched_scan.target == "test_target":
            print("  ✅ PASS: Fetched scan successfully by ID.")
            passed.append("get_scan")
        else:
            print("  ❌ FAIL: Fetch scan failed.")
            failed.append(("get_scan", "Scan not found or target mismatch"))

        # 3. Add Finding (with fixes)
        finding = repository.add_finding(
            db=db,
            scan_id=scan_id,
            vuln_type="SQL Injection",
            severity="critical",
            description="Vulnerable code concatenates string",
            file_path="db.py",
            line_number=42,
            vulnerable_code="SELECT * FROM users WHERE id = " + "user_id",
            ai_explanation="Use parameterized query",
            ai_fix="db.execute('SELECT * FROM users WHERE id = :id', {'id': user_id})",
            confidence=0.95
        )
        if finding and finding.finding_id:
            print(f"  ✅ PASS: Added finding. finding_id: {finding.finding_id}")
            passed.append("add_finding")
            finding_id = finding.finding_id
        else:
            print("  ❌ FAIL: Add finding failed.")
            failed.append(("add_finding", "Finding not generated"))
            return passed, failed

        # 4. Update Finding
        updated_finding = repository.update_finding(db, finding_id, is_false_positive=True, confidence=0.1)
        if updated_finding and updated_finding.is_false_positive is True and updated_finding.confidence == 0.1:
            print("  ✅ PASS: Updated finding successfully.")
            passed.append("update_finding")
        else:
            print(f"  ❌ FAIL: Update finding failed. Updated state: {updated_finding}")
            failed.append(("update_finding", "Finding fields not updated"))

        # 5. Retrieve fixes
        findings = repository.get_findings_by_scan(db, scan_id)
        if len(findings) > 0 and findings[0].fixed_code:
            print("  ✅ PASS: Retrieved finding with fixes successfully.")
            passed.append("retrieve_fixes")
        else:
            print("  ❌ FAIL: Retrieve fixes failed.")
            failed.append(("retrieve_fixes", "No fixes stored in findings"))

        # 6. Delete Scan & verify cleanup
        repository.delete_scan(db, scan_id)
        deleted_scan = repository.get_scan(db, scan_id)
        if deleted_scan is None:
             print("  ✅ PASS: Deleted scan successfully.")
             passed.append("delete_scan")
        else:
             print("  ❌ FAIL: Delete scan failed.")
             failed.append(("delete_scan", "Scan still exists after deletion"))

    except Exception as e:
        print(f"  ❌ FAIL: SQL query failed: {e}")
        failed.append(("SQL execution check", str(e)))
    finally:
        db.close()

    return passed, failed

if __name__ == "__main__":
    passed, failed = test_database()
    sys.exit(len(failed))
