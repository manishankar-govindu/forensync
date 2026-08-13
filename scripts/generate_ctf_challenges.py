# generate_ctf_challenges.py - Generate real CTF challenge evidence files
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CTF_DIR = os.path.join(BASE_DIR, 'evidence', 'ctf')
os.makedirs(CTF_DIR, exist_ok=True)

def generate_challenges():
    print("=" * 60)
    print("  ForenSync - CTF Challenge File Generator")
    print("=" * 60)

    # Challenge 1: Raw disk image (.dd) containing deleted PNG image with embedded flag
    sc1_path = os.path.join(CTF_DIR, 'ctf_scenario_1_deleted_file.dd')
    png_header = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    png_payload = b"SECRET_PASSPHRASE_CONTAINING_FLAG{CARVED_JPEG_FOUND_2026}_END_OF_IMAGE_DATA" * 5
    png_footer = bytes([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82])

    with open(sc1_path, 'wb') as f:
        f.write(b"UNALLOCATED_SECTOR_HEADER_BLOCK_" * 10)
        f.write(png_header + png_payload + png_footer)
        f.write(b"UNALLOCATED_SECTOR_FOOTER_BLOCK_" * 10)

    print(f"[OK] Created Challenge 1 disk image: {sc1_path} ({os.path.getsize(sc1_path)} bytes)")

    # Challenge 2: EXIF JPEG photograph with GPS location metadata tag & flag
    sc2_path = os.path.join(CTF_DIR, 'ctf_scenario_2_suspect_photo.jpg')
    jpeg_header = bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x60, 0x00, 0x60, 0x00, 0x00])
    exif_payload = b"EXIF_METADATA_GPS_LAT_22.3072_LON_73.1812_COMMENT_FLAG{GPS_22.3072_73.1812}"
    jpeg_footer = bytes([0xFF, 0xD9])

    with open(sc2_path, 'wb') as f:
        f.write(jpeg_header + exif_payload + jpeg_footer)

    print(f"[OK] Created Challenge 2 EXIF photo: {sc2_path} ({os.path.getsize(sc2_path)} bytes)")

    # Challenge 3: Tampered log dump file (.dd) with integrity flag
    sc3_path = os.path.join(CTF_DIR, 'ctf_scenario_3_integrity_log.dd')
    with open(sc3_path, 'wb') as f:
        f.write(b"[2026-07-28 07:00:00] SYSTEM_AUDIT_LOG_START\n")
        f.write(b"[2026-07-28 07:05:12] INTEGRITY_CHECK_PASS SHA256_HASH_VERIFIED\n")
        f.write(b"FLAG{INTEGRITY_VERIFIED_SHA256}\n")
        f.write(b"[2026-07-28 07:10:00] SYSTEM_AUDIT_LOG_END\n")

    print(f"[OK] Created Challenge 3 log dump: {sc3_path} ({os.path.getsize(sc3_path)} bytes)")
    print("\n[OK] All CTF Challenge evidence files generated successfully!")

if __name__ == '__main__':
    generate_challenges()
