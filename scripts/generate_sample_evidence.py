# generate_sample_evidence.py - Generate realistic forensic sample evidence files
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE_DIR = os.path.join(BASE_DIR, 'evidence', 'samples')
os.makedirs(EVIDENCE_DIR, exist_ok=True)

def generate_sample_files():
    print("=" * 60)
    print("  ForenSync - Sample Evidence File Generator")
    print("=" * 60)

    # 1. Raw disk dump containing embedded JPEG & PNG signatures
    disk_image_path = os.path.join(EVIDENCE_DIR, 'suspect_disk_dump.dd')
    jpeg_header = bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46])
    jpeg_body = b'CONFIDENTIAL_EVIDENCE_PHOTO_DATA_' * 20
    jpeg_footer = bytes([0xFF, 0xD9])

    png_header = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    png_body = b'SECRET_PASSPHRASE_IMAGE_DATA_' * 15
    png_footer = bytes([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82])

    with open(disk_image_path, 'wb') as f:
        f.write(b'UNALLOCATED_SECTOR_START_' * 5)
        f.write(jpeg_header + jpeg_body + jpeg_footer)
        f.write(b'FILLER_BYTES_' * 10)
        f.write(png_header + png_body + png_footer)
        f.write(b'UNALLOCATED_SECTOR_END_' * 5)

    print(f"[OK] Created sample disk dump: {disk_image_path} ({os.path.getsize(disk_image_path)} bytes)")

    # 2. Text evidence file for hash verification & entropy analysis
    log_file_path = os.path.join(EVIDENCE_DIR, 'network_security_audit.log')
    with open(log_file_path, 'w', encoding='utf-8') as f:
        f.write("[2026-07-27 10:14:22] LOGIN SUCCESS user=admin ip=192.168.1.105\n")
        f.write("[2026-07-27 10:15:01] FILE_TRANSFER source=/tmp/data.tar.gz bytes=145209\n")
        f.write("[2026-07-27 10:16:45] SUSPICIOUS_EXEC command='bcwipe -r /var/log/messages'\n")
        f.write("FLAG{INTEGRITY_VERIFIED_SHA256}\n")

    print(f"[OK] Created sample security log: {log_file_path} ({os.path.getsize(log_file_path)} bytes)")
    print("\n[OK] Sample evidence ready for ingestion and testing!")

if __name__ == '__main__':
    generate_sample_files()
