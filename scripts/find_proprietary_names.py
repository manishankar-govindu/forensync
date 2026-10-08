import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TERMS = ['autopsy', 'belkasoft', 'ftk']
SKIP = ['venv', '.git', '__pycache__', '.pytest_cache']

matches = []
for root, dirs, files in os.walk(ROOT):
    if any(s in root for s in SKIP):
        continue
    for fname in files:
        if fname.endswith(('.py', '.html', '.md', '.json', '.txt')):
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    for idx, line in enumerate(f, 1):
                        lower_line = line.lower()
                        for t in TERMS:
                            if t in lower_line:
                                matches.append((fpath, idx, line.strip()))
                                break
            except Exception as e:
                pass

out_path = os.path.join(ROOT, 'scripts', 'proprietary_matches.txt')
with open(out_path, 'w', encoding='utf-8') as out:
    out.write(f"Found {len(matches)} occurrences:\n")
    for fpath, line_no, content in matches:
        rel = os.path.relpath(fpath, ROOT)
        out.write(f"[{rel}:{line_no}] {content}\n")

print(f"Wrote {len(matches)} occurrences to {out_path}")
