import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
db_paths = [
    os.path.join(BASE_DIR, 'instance', 'forensync.db'),
    os.path.join(BASE_DIR, 'backend', 'instance', 'forensync.db')
]

for p in db_paths:
    if os.path.exists(p):
        print("=" * 60)
        print(f"Inspecting DB: {p} ({os.path.getsize(p)} bytes)")
        print("=" * 60)
        conn = sqlite3.connect(p)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [t[0] for t in cur.fetchall()]
        print("Tables:", tables)
        for t in tables:
            if t.startswith('sqlite_'): continue
            cur.execute(f"SELECT COUNT(*) FROM {t}")
            cnt = cur.fetchone()[0]
            print(f" - Table {t}: {cnt} rows")
        conn.close()
