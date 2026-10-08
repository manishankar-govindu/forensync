import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXTS = ('.py', '.html', '.md', '.yml', '.yaml', '.json', '.txt', '.example')

cleaned_count = 0
for root, dirs, files in os.walk(ROOT):
    if 'venv' in root or '.git' in root:
        continue
    for fname in files:
        if fname.endswith(EXTS):
            fpath = os.path.join(root, fname)
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            new_lines = [line.rstrip() + '\n' for line in lines]
            # Ensure single newline at end of file if not empty
            if new_lines and not new_lines[-1].endswith('\n'):
                new_lines[-1] += '\n'

            with open(fpath, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
            cleaned_count += 1

print(f"[OK] Cleaned trailing whitespace across {cleaned_count} source files.")
