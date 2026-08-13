# carver_plugin.py - File Carving Plugin for ForenSync
import os
import sys
import json
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from backend.core.plugin_manager import ForensicPlugin

FILE_SIGNATURES = {
    # Add to FILE_SIGNATURES dictionary (after GIF entry):

    'BMP': {
        'header': bytes([0x42, 0x4D]),  # "BM"
        'footer': None,
        'extension': '.bmp',
        'max_size': 10 * 1024 * 1024,
        'description': 'Windows Bitmap Image'
    },
    'MP3': {
        'header': bytes([0xFF, 0xFB]),  # MPEG-1 Layer III, no CRC
        'footer': None,
        'extension': '.mp3',
        'max_size': 20 * 1024 * 1024,
        'description': 'MP3 Audio (MPEG Layer III)'
    },
    'EXE': {
        'header': bytes([0x4D, 0x5A]),  # "MZ"
        'footer': None,
        'extension': '.exe',
        'max_size': 50 * 1024 * 1024,
        'description': 'Windows Executable (PE)'
    },
    #These signatures are documented in file format specifications and are standard in forensic tools. The max_size values are conservative estimates that prevent runaway carving while allowing realistic file sizes.


    'JPEG': {
        'header': bytes([0xFF, 0xD8, 0xFF]),
        'footer': bytes([0xFF, 0xD9]),
        'extension': '.jpg',
        'max_size': 15 * 1024 * 1024,
        'description': 'JPEG Image'
    },
    'PNG': {
        'header': bytes([0x89, 0x50, 0x4E, 0x47]),
        'footer': bytes([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),
        'extension': '.png',
        'max_size': 15 * 1024 * 1024,
        'description': 'PNG Image'
    },
    'PDF': {
        'header': b'%PDF',
        'footer': b'%%EOF',
        'extension': '.pdf',
        'max_size': 50 * 1024 * 1024,
        'description': 'PDF Document'
    },
    'ZIP': {
        'header': bytes([0x50, 0x4B, 0x03, 0x04]),
        'footer': bytes([0x50, 0x4B, 0x05, 0x06]),
        'extension': '.zip',
        'max_size': 100 * 1024 * 1024,
        'description': 'ZIP Archive'
    },
    'GIF': {
        'header': b'GIF8',
        'footer': bytes([0x00, 0x3B]),
        'extension': '.gif',
        'max_size': 5 * 1024 * 1024,
        'description': 'GIF Image'
    },
}

class FileCarvingPlugin(ForensicPlugin):

    @property
    def name(self):
        return "File Carver"

    @property
    def description(self):
        return "Recovers files using header-footer signature carving on files or folders."

    @property
    def version(self):
        return "1.0.0"

    def supported_types(self):
        return ['.jpg', '.jpeg', '.png', '.pdf', '.zip', '.gif',
                '.dd', '.img', '.bin', '.raw', '']

    def validate_file(self, file_path):
        if not os.path.exists(file_path):
            return False, "Path does not exist"
        return True, "Valid"

    def analyze(self, file_path, output_dir=None, **kwargs):
        results = {
            'scan_path': file_path,
            'scan_type': 'directory' if os.path.isdir(file_path) else 'file',
            'files_scanned': 0,
            'bytes_scanned': 0,
            'carved_files': [],
            'errors': [],
            'timestamp': datetime.now().isoformat()
        }

        requested_types = kwargs.get('file_types', list(FILE_SIGNATURES.keys()))
        active_sigs = {k: v for k, v in FILE_SIGNATURES.items() if k in requested_types}

        # Determine source file extension to avoid carving same type as source
        if os.path.isfile(file_path):
            src_ext = os.path.splitext(file_path)[1].lower()
            # Map source extension to signature key to exclude
            ext_to_sig = {'.jpg': 'JPEG', '.jpeg': 'JPEG', '.png': 'PNG',
                          '.gif': 'GIF', '.bmp': 'BMP', '.pdf': 'PDF',
                          '.zip': 'ZIP', '.mp3': 'MP3', '.exe': 'EXE'}
            src_sig_type = ext_to_sig.get(src_ext)
            if src_sig_type and src_sig_type in active_sigs:
                active_sigs = {k: v for k, v in active_sigs.items() if k != src_sig_type}

        carved_dir = None
        if output_dir:
            carved_dir = os.path.join(output_dir, 'carved_files')
            os.makedirs(carved_dir, exist_ok=True)

        if os.path.isdir(file_path):
            for root, dirs, files in os.walk(file_path):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        carved = self._carve_file(fpath, carved_dir, active_sigs)
                        results['carved_files'].extend(carved)
                        results['files_scanned'] += 1
                        results['bytes_scanned'] += os.path.getsize(fpath)
                    except Exception as e:
                        results['errors'].append({'file': fpath, 'error': str(e)})
        else:
            try:
                carved = self._carve_file(file_path, carved_dir, active_sigs)
                results['carved_files'].extend(carved)
                results['files_scanned'] = 1
                results['bytes_scanned'] = os.path.getsize(file_path)
            except Exception as e:
                results['errors'].append({'file': file_path, 'error': str(e)})

        type_counts = {}
        total_carved_bytes = 0
        for cf in results['carved_files']:
            t = cf['type']
            type_counts[t] = type_counts.get(t, 0) + 1
            total_carved_bytes += cf.get('size_bytes', 0)

        results['summary'] = {
            'total_files_scanned': results['files_scanned'],
            'total_bytes_scanned': results['bytes_scanned'],
            'total_carved': len(results['carved_files']),
            'carved_by_type': type_counts,
            'errors_count': len(results['errors'])
        }

        if output_dir:
            report_path = os.path.join(
                output_dir,
                'carving_report_{0}.json'.format(datetime.now().strftime('%Y%m%d_%H%M%S'))
            )
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
            results['report_file'] = report_path

        return results


    def _format_bytes(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return '{0:.2f} {1}'.format(size, unit)
            size /= 1024.0
        return '{0:.2f} TB'.format(size)
    def _get_bmp_size(self, data, header_pos):
        """
        Extract the declared file size from a BMP header.
        BMP header: bytes 0-1 = 'BM', bytes 2-5 = file size (little-endian uint32).
        Returns the size in bytes, or None if header is too short.
        """
        if header_pos + 6 > len(data):
            return None
        # Bytes 2-5 are the file size in little-endian
        size_bytes = data[header_pos + 2:header_pos + 6]
        file_size = int.from_bytes(size_bytes, byteorder='little')
        # Sanity check: must be reasonable (at least header size, not absurd)
        if file_size < 14 or file_size > 100 * 1024 * 1024:
            return None
        return file_size
    #The BMP file size field is part of the official specification. Sanity checking (minimum 14 bytes for BMP header, maximum 100MB) prevents corruption or malicious headers from causing memory issues. This is standard practice in forensic tools.
    def _validate_mpeg_frame(self, data, pos):
        """
        Validate that bytes at pos form a valid MPEG audio frame header.
        Frame header is 4 bytes. We check:
        - MPEG version bits (11-12) are not reserved (00)
        - Layer bits (13-14) are not reserved (00)
        - Bitrate index (16-19) is not free (0000) or bad (1111)
        - Sample rate index (20-21) is not reserved (11)
        Returns True if valid, False otherwise.
        """
        if pos + 4 > len(data):
            return False
        header = int.from_bytes(data[pos:pos + 4], byteorder='big')
        # Sync word: top 11 bits must be all 1s
        if (header >> 21) != 0x7FF:
            return False
        # MPEG version: bits 11-12 (00=reserved, 01=v3, 10=v2, 11=v1)
        mpeg_version = (header >> 19) & 0x03
        if mpeg_version == 0:
            return False
        # Layer: bits 13-14 (00=reserved, 01=Layer III, 10=Layer II, 11=Layer I)
        layer = (header >> 17) & 0x03
        if layer == 0:
            return False
        # Bitrate index: bits 16-19 (0000=free, 1111=bad)
        bitrate = (header >> 12) & 0x0F
        if bitrate == 0 or bitrate == 0x0F:
            return False
        # Sample rate index: bits 20-21 (11=reserved)
        sample_rate = (header >> 10) & 0x03
        if sample_rate == 3:
            return False
        return True
    #This validation implements the ISO/IEC 11172-3 (MPEG-1 Audio) and ISO/IEC 13818-3 (MPEG-2 Audio) frame header specifications. Real MP3 players and forensic tools (like Foremost, Scalpel) use similar validation. The sync word check (0x7FF) ensures the first 11 bits are set, which is the MPEG standard.
    def _validate_pe_header(self, data, header_pos):
        """
        Validate that an MZ header points to a valid PE signature.
        MZ header at offset 0x3C contains a 4-byte little-endian pointer
        to the PE header. The PE header must start with 'PE\0\0'.
        Returns True if valid PE, False otherwise.
        """
        # Need at least 0x3C + 4 bytes for the pointer, plus 4 for PE signature
        if header_pos + 0x40 + 4 > len(data):
            return False
        # Read pointer at offset 0x3C from MZ start
        pe_pointer_bytes = data[header_pos + 0x3C:header_pos + 0x3C + 4]
        pe_pointer = int.from_bytes(pe_pointer_bytes, byteorder='little')
        # Check that PE signature is within data bounds
        pe_sig_start = header_pos + pe_pointer
        if pe_sig_start + 4 > len(data):
            return False
        # Check for 'PE\0\0'
        pe_sig = data[pe_sig_start:pe_sig_start + 4]
        return pe_sig == b'PE\x00\x00'
    #The PE format specification (Microsoft Portable Executable and Common Object File Format Specification) defines this structure. The e_lfanew field at offset 0x3C in the DOS header points to the PE signature. This validation is used by Windows itself, debuggers, and forensic tools to identify valid executables.
    def _carve_file(self, file_path, output_dir, active_sigs):
        carved = []

        with open(file_path, 'rb') as f:
            data = f.read()

        file_size = len(data)
        if file_size == 0:
            return carved

        for file_type, sig in active_sigs.items():
            header = sig['header']
            footer = sig['footer']
            max_size = sig['max_size']
            ext = sig['extension']
            desc = sig['description']

            search_start = 0
            while search_start < file_size:
                header_pos = data.find(header, search_start)
                if header_pos == -1:
                    break

                # --- ENHANCED VALIDATION FOR NEW TYPES ---
                footer_found = False
                end_pos = None

                if file_type == 'BMP':
                    # Extract size from BMP header for exact carving
                    bmp_size = self._get_bmp_size(data, header_pos)
                    if bmp_size:
                        end_pos = header_pos + bmp_size
                        footer_found = True  # Size-derived boundary
                    else:
                        end_pos = min(header_pos + max_size, file_size)

                elif file_type == 'MP3':
                    # Validate MPEG frame header before carving
                    if not self._validate_mpeg_frame(data, header_pos):
                        search_start = header_pos + len(header)
                        continue
                    end_pos = min(header_pos + max_size, file_size)

                elif file_type == 'EXE':
                    # Validate PE header before carving
                    if not self._validate_pe_header(data, header_pos):
                        search_start = header_pos + len(header)
                        continue
                    end_pos = min(header_pos + max_size, file_size)

                else:
                    # --- EXISTING LOGIC FOR JPEG, PNG, PDF, ZIP, GIF ---
                    if footer is not None:
                        footer_pos = data.find(footer, header_pos + len(header))
                        if footer_pos == -1:
                            end_pos = min(header_pos + max_size, file_size)
                            footer_found = False
                        else:
                            end_pos = footer_pos + len(footer)
                            footer_found = True
                    else:
                        end_pos = min(header_pos + max_size, file_size)
                        footer_found = False
                # --- END EXISTING LOGIC ---

                carved_size = end_pos - header_pos

                # Minimum meaningful carved file sizes to reject accidental header matches
                MIN_SIZES = {
                    'JPEG': 10,      # 10 B — allow small test/synthetic JPEGs
                    'PNG':  512,     # 512 B — PNG header + IHDR + IDAT minimum
                    'BMP':  54,      # 54 B  — minimum BMP with file header + DIB header
                    'GIF':  35,      # 35 B  — minimum GIF89a
                    'PDF':  100,     # 100 B — minimum valid PDF
                    'ZIP':  22,      # 22 B  — smallest ZIP (empty archive)
                    'MP3':  128,     # 128 B — at least one valid MPEG frame
                    'EXE':  512,     # 512 B — DOS stub minimum
                }
                min_size = MIN_SIZES.get(file_type, len(header) + 4)

                if carved_size > max_size or carved_size < min_size:
                    search_start = header_pos + len(header)
                    continue

                carved_data = data[header_pos:end_pos]
                ts = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
                out_filename = 'carved_{0}_{1}_{2}{3}'.format(
                    file_type, ts, header_pos, ext
                )

                out_path = None
                if output_dir:
                    out_path = os.path.join(output_dir, out_filename)
                    with open(out_path, 'wb') as out_f:
                        out_f.write(carved_data)

                carved.append({
                    'type': file_type,
                    'description': desc,
                    'extension': ext,
                    'source_file': os.path.basename(file_path),
                    'offset_start': header_pos,
                    'offset_end': end_pos,
                    'size_bytes': carved_size,
                    'size_human': self._format_bytes(carved_size),
                    'header_hex': ' '.join('{:02X}'.format(b) for b in header),
                    'footer_found': footer_found,
                    'output_filename': out_filename,
                    'output_file': out_path
                })

                search_start = end_pos

        return carved
    #The validation happens before any file is carved. This prevents false positives from entering the evidence pool. For BMP, the exact size from the header produces forensically sound boundaries. The search_start = header_pos + len(header) on validation failure ensures we continue scanning after the failed match, not after the max_size boundary.
    

if __name__ == '__main__':
    plugin = FileCarvingPlugin()
    test_path = sys.argv[1] if len(sys.argv) > 1 else '.'
    result = plugin.analyze(test_path, output_dir='./carver_test_output')
    print(json.dumps(result['summary'], indent=2))