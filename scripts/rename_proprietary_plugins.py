import os
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 1. Update plugins/disk/autopsy_plugin.py content and rename
old_autopsy = os.path.join(ROOT, 'plugins', 'disk', 'autopsy_plugin.py')
new_autopsy = os.path.join(ROOT, 'plugins', 'disk', 'disk_structure_plugin.py')

if os.path.exists(old_autopsy):
    with open(old_autopsy, 'r', encoding='utf-8') as f:
        content = f.read()
    content = content.replace('FLAG{AUTOPSY_EMAIL_EXTRACTED_EVIDENCE}', 'FLAG{DISK_EMAIL_EXTRACTED_EVIDENCE}')
    content = content.replace('(like Autopsy does)', '(across disk sectors)')
    with open(new_autopsy, 'w', encoding='utf-8') as f:
        f.write(content)
    os.remove(old_autopsy)
    print(f"[OK] Renamed {old_autopsy} -> {new_autopsy}")

# 2. Update plugins/network/belkasoft_plugin.py content and rename
old_belka = os.path.join(ROOT, 'plugins', 'network', 'belkasoft_plugin.py')
new_belka = os.path.join(ROOT, 'plugins', 'network', 'network_artifact_plugin.py')

if os.path.exists(old_belka):
    with open(old_belka, 'r', encoding='utf-8') as f:
        content = f.read()
    content = content.replace('FLAG{BELKASOFT_EMAIL_EXTRACTED_EVIDENCE}', 'FLAG{NETWORK_EMAIL_EXTRACTED_EVIDENCE}')
    with open(new_belka, 'w', encoding='utf-8') as f:
        f.write(content)
    os.remove(old_belka)
    print(f"[OK] Renamed {old_belka} -> {new_belka}")

print("[DONE] Plugins successfully renamed to legally clean names.")
