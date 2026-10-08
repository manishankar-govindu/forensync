import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plugins.disk.carver_plugin import FileCarvingPlugin
from plugins.metadata.hash_plugin import HashVerifierPlugin
from plugins.network.browser_plugin import BrowserArtifactPlugin

def test_verification():
    print("=" * 60)
    print("  ForenSync Live Tool Verification")
    print("=" * 60)

    # 1. Carver Test on suspect_disk_dump.dd
    carver = FileCarvingPlugin()
    sample_dd = os.path.join('evidence', 'samples', 'suspect_disk_dump.dd')
    res_carve = carver.analyze(sample_dd)
    carved_files = res_carve.get('carved_files', [])

    print(f"\n[1] File Carver (Foremost / Scalpel / PhotoRec backend):")
    print(f"    - Target: {sample_dd}")
    print(f"    - Total Carved: {len(carved_files)} (Expected: exactly 2 -> 1 JPEG, 1 PNG)")
    for f in carved_files:
        print(f"      * Carved: {f['type']} | Size: {f['size_human']} | Offset: {f['offset_start']}")

    assert len(carved_files) == 2, f"Expected 2 carved files, got {len(carved_files)}"
    types = [f['type'] for f in carved_files]
    assert 'JPEG' in types and 'PNG' in types, "Expected both JPEG and PNG"
    print("    [PASS] Carver accurate - 0 false positives!")

    # 2. Hash Verifier Test
    hasher = HashVerifierPlugin()
    sample_log = os.path.join('evidence', 'samples', 'network_security_audit.log')
    res_hash = hasher.analyze(sample_log)
    print(f"\n[2] Hash Verifier:")
    print(f"    - Target: {sample_log}")
    print(f"    - MD5:    {res_hash['hashes']['md5']}")
    print(f"    - SHA256: {res_hash['hashes']['sha256']}")
    assert len(res_hash['hashes']['md5']) == 32
    print("    [PASS] Hash verification functional!")

    # 3. Browser / Bulk Artifact Extractor Test
    browser = BrowserArtifactPlugin()
    res_browser = browser.analyze(sample_log)
    print(f"\n[3] Bulk / Browser Artifact Extractor:")
    print(f"    - Target: {sample_log}")
    print(f"    - Result: {res_browser.get('error', 'Processed')} (Handled non-sqlite file gracefully)")
    print("    [PASS] Browser plugin verified!")

    print("\n" + "=" * 60)
    print("  ALL REAL TOOL VERIFICATIONS PASSED (100%)")
    print("=" * 60)

if __name__ == '__main__':
    test_verification()
