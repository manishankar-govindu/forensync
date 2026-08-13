# reset_environment.py - Reset all evidence, cases, reports, and database tables
import os
import shutil
import sqlite3

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'instance', 'forensync.db')

def reset_all():
    print("=" * 60)
    print("  ForenSync - Full Workspace Reset Utility")
    print("=" * 60)

    # 1. Clear database records (cases, evidence, audit_logs)
    if os.path.exists(DB_PATH):
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Wipe table records
            cursor.execute("DELETE FROM evidence;")
            cursor.execute("DELETE FROM cases;")
            cursor.execute("DELETE FROM audit_log;")
            conn.commit()
            conn.close()
            print("[OK] Wiped all cases, evidence metadata, and audit logs from database.")
        except Exception as e:
            print(f"[WARN] Error clearing database tables: {e}")

    # 2. Clear evidence directory (except CTF challenge folder)
    evidence_dir = os.path.join(BASE_DIR, 'evidence')
    if os.path.exists(evidence_dir):
        for item in os.listdir(evidence_dir):
            item_path = os.path.join(evidence_dir, item)
            if item == 'ctf':
                continue  # Preserve CTF challenge files
            try:
                if os.path.isfile(item_path):
                    os.remove(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path, ignore_errors=True)
            except Exception as e:
                print(f"[WARN] Could not remove {item}: {e}")
        print("[OK] Cleared all uploaded evidence files.")

    # 3. Clear reports directory
    reports_dir = os.path.join(BASE_DIR, 'reports')
    if os.path.exists(reports_dir):
        for item in os.listdir(reports_dir):
            item_path = os.path.join(reports_dir, item)
            try:
                if os.path.isfile(item_path):
                    os.remove(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path, ignore_errors=True)
            except Exception as e:
                print(f"[WARN] Could not remove {item}: {e}")
        print("[OK] Cleared all generated reports and carved outputs.")

    print("\n[COMPLETE] Workspace is 100% clean! Refresh your browser or restart server.")

if __name__ == '__main__':
    reset_all()
