# test_plugins.py - Unit tests for ForenSync plugins
# Run from project root: python -m pytest tests/ -v
# Or run directly:       python tests/test_plugins.py
# Compatible with Python 3.9 (Rule 1).

import os
import sys
import json
import tempfile
import unittest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# =============================================================================
# HASH VERIFIER PLUGIN TESTS
# =============================================================================

class TestHashVerifierPlugin(unittest.TestCase):
    """Tests for plugins/metadata/hash_plugin.py"""

    def setUp(self):
        from plugins.metadata.hash_plugin import HashVerifierPlugin
        self.plugin = HashVerifierPlugin()

        # Create a temp file with known content for testing
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, 'test_file.txt')
        with open(self.test_file, 'wb') as f:
            f.write(b'ForenSync test content 12345')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_plugin_name(self):
        self.assertEqual(self.plugin.name, 'Hash Verifier')

    def test_plugin_version(self):
        self.assertIsNotNone(self.plugin.version)

    def test_validate_file_exists(self):
        valid, msg = self.plugin.validate_file(self.test_file)
        self.assertTrue(valid, 'Expected valid=True for existing file, got: ' + msg)

    def test_validate_file_not_exists(self):
        valid, msg = self.plugin.validate_file('/nonexistent/path/file.txt')
        self.assertFalse(valid)

    def test_hashes_are_computed(self):
        result = self.plugin.analyze(self.test_file)
        self.assertIn('hashes', result)
        self.assertIn('md5', result['hashes'])
        self.assertIn('sha1', result['hashes'])
        self.assertIn('sha256', result['hashes'])
        self.assertIn('sha512', result['hashes'])

    def test_md5_is_correct_length(self):
        result = self.plugin.analyze(self.test_file)
        self.assertEqual(len(result['hashes']['md5']), 32)

    def test_sha256_is_correct_length(self):
        result = self.plugin.analyze(self.test_file)
        self.assertEqual(len(result['hashes']['sha256']), 64)

    def test_entropy_is_computed(self):
        result = self.plugin.analyze(self.test_file)
        self.assertIn('entropy', result)
        self.assertIsInstance(result['entropy'], float)
        # Entropy of text should be between 0 and 8
        self.assertGreaterEqual(result['entropy'], 0)
        self.assertLessEqual(result['entropy'], 8)

    def test_hash_verification_match(self):
        result = self.plugin.analyze(self.test_file)
        known_md5 = result['hashes']['md5']
        # Re-analyze with expected hash
        result2 = self.plugin.analyze(self.test_file, expected_hash=known_md5)
        self.assertIsNotNone(result2['verification'])
        self.assertTrue(result2['verification']['match'])

    def test_hash_verification_mismatch(self):
        result = self.plugin.analyze(
            self.test_file, expected_hash='0' * 32
        )
        self.assertIsNotNone(result['verification'])
        self.assertFalse(result['verification']['match'])

    def test_output_file_saved(self):
        result = self.plugin.analyze(self.test_file, output_dir=self.temp_dir)
        self.assertIn('output_file', result)
        self.assertTrue(os.path.isfile(result['output_file']))


# =============================================================================
# FILE CARVING PLUGIN TESTS
# =============================================================================

class TestFileCarvingPlugin(unittest.TestCase):
    """Tests for plugins/disk/carver_plugin.py"""
    def test_carves_bmp_from_binary(self):
        """BMP with embedded size must be carved with exact size."""
        path = os.path.join(self.temp_dir, 'test_with_bmp.bin')
        # BMP header: "BM" + 4-byte size (little-endian) + rest
        bmp_size = 54 + 12  # header + 4x3 pixel data (simplified)
        header = bytes([0x42, 0x4D]) + bmp_size.to_bytes(4, 'little')
        body = b'\x00' * (bmp_size - 6)  # Fill to declared size
        filler = b'X' * 20
        with open(path, 'wb') as f:
            f.write(filler + header + body + filler)
        result = self.plugin.analyze(path)
        bmp_carved = [c for c in result['carved_files'] if c['type'] == 'BMP']
        self.assertGreater(len(bmp_carved), 0)
        self.assertEqual(bmp_carved[0]['size_bytes'], bmp_size)

    def test_mp3_validation_rejects_invalid(self):
        """Random FF FB bytes without valid MPEG frame should not carve."""
        path = os.path.join(self.temp_dir, 'fake_mp3.bin')
        with open(path, 'wb') as f:
            f.write(b'X' * 10 + bytes([0xFF, 0xFB, 0x00, 0x00]) + b'Y' * 10)
        result = self.plugin.analyze(path)
        mp3_carved = [c for c in result['carved_files'] if c['type'] == 'MP3']
        self.assertEqual(len(mp3_carved), 0)

    def test_exe_validation_rejects_random_mz(self):
        """Random MZ bytes without PE signature should not carve."""
        path = os.path.join(self.temp_dir, 'fake_exe.bin')
        with open(path, 'wb') as f:
            f.write(b'X' * 10 + bytes([0x4D, 0x5A]) + b'\x00' * 0x3C + b'NOPE' + b'Y' * 10)
        result = self.plugin.analyze(path)
        exe_carved = [c for c in result['carved_files'] if c['type'] == 'EXE']
        self.assertEqual(len(exe_carved), 0)

    
    def setUp(self):
        from plugins.disk.carver_plugin import FileCarvingPlugin
        self.plugin = FileCarvingPlugin()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _make_test_file_with_jpeg(self):
        """Create a binary file containing an embedded JPEG signature."""
        path = os.path.join(self.temp_dir, 'test_with_jpeg.bin')
        jpeg_header = bytes([0xFF, 0xD8, 0xFF, 0xE0])
        jpeg_body = b'A' * 100
        jpeg_footer = bytes([0xFF, 0xD9])
        filler_before = b'X' * 50
        filler_after = b'Y' * 50
        with open(path, 'wb') as f:
            f.write(filler_before + jpeg_header + jpeg_body + jpeg_footer + filler_after)
        return path

    def _make_plain_text_file(self):
        """Create a plain text file with no embedded file signatures."""
        path = os.path.join(self.temp_dir, 'plain.txt')
        with open(path, 'w') as f:
            f.write('This is just plain text with no magic bytes.')
        return path

    def test_plugin_name(self):
        self.assertEqual(self.plugin.name, 'File Carver')

    def test_plugin_version(self):
        self.assertIsNotNone(self.plugin.version)

    def test_validate_accepts_any_file(self):
        path = self._make_plain_text_file()
        valid, msg = self.plugin.validate_file(path)
        self.assertTrue(valid)

    def test_validate_accepts_directory(self):
        valid, msg = self.plugin.validate_file(self.temp_dir)
        self.assertTrue(valid)

    def test_validate_rejects_nonexistent(self):
        valid, msg = self.plugin.validate_file('/no/such/path')
        self.assertFalse(valid)

    def test_carves_jpeg_from_binary(self):
        """Core test: carver must find JPEG header+footer in raw bytes."""
        path = self._make_test_file_with_jpeg()
        result = self.plugin.analyze(path)
        jpeg_carved = [c for c in result['carved_files'] if c['type'] == 'JPEG']
        self.assertGreater(
            len(jpeg_carved), 0,
            'Expected at least one JPEG to be carved from the test binary'
        )

    def test_carved_file_has_correct_offset(self):
        """Carved file offset must point to where the header was found."""
        path = self._make_test_file_with_jpeg()
        result = self.plugin.analyze(path)
        jpeg_carved = [c for c in result['carved_files'] if c['type'] == 'JPEG']
        if jpeg_carved:
            # Header was placed 50 bytes into the file
            self.assertEqual(jpeg_carved[0]['offset_start'], 50)

    def test_no_false_positives_in_plain_text(self):
        """Plain text files should produce very few or no carved artifacts."""
        path = self._make_plain_text_file()
        result = self.plugin.analyze(path)
        # There might be accidental byte matches, but total carved should be 0
        # for a short plain text file with no magic bytes
        self.assertEqual(
            result['summary']['total_carved'], 0,
            'Expected 0 carved files from plain text'
        )

    def test_scans_directory(self):
        """Carver must process all files in a folder."""
        self._make_plain_text_file()
        self._make_test_file_with_jpeg()
        result = self.plugin.analyze(self.temp_dir)
        self.assertGreaterEqual(result['files_scanned'], 2)

    def test_saves_carved_file_to_output(self):
        """Carved bytes must be saved as a real file."""
        path = self._make_test_file_with_jpeg()
        out_dir = os.path.join(self.temp_dir, 'carved_out')
        result = self.plugin.analyze(path, output_dir=out_dir)
        jpeg_carved = [c for c in result['carved_files'] if c['type'] == 'JPEG']
        if jpeg_carved:
            carved_path = jpeg_carved[0].get('output_file')
            self.assertIsNotNone(carved_path)
            self.assertTrue(os.path.isfile(carved_path))

    def test_summary_is_present(self):
        path = self._make_plain_text_file()
        result = self.plugin.analyze(path)
        self.assertIn('summary', result)
        self.assertIn('total_carved', result['summary'])
        self.assertIn('total_files_scanned', result['summary'])

    def test_report_json_saved(self):
        path = self._make_plain_text_file()
        out_dir = os.path.join(self.temp_dir, 'report_out')
        result = self.plugin.analyze(path, output_dir=out_dir)
        self.assertIn('report_file', result)
        self.assertTrue(os.path.isfile(result['report_file']))


# =============================================================================
# BROWSER ARTIFACT PLUGIN TESTS
# =============================================================================

class TestBrowserArtifactPlugin(unittest.TestCase):
    """Tests for plugins/network/browser_plugin.py"""

    def setUp(self):
        from plugins.network.browser_plugin import BrowserArtifactPlugin
        self.plugin = BrowserArtifactPlugin()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_plugin_name(self):
        self.assertEqual(self.plugin.name, 'Browser Artifact Extractor')

    def test_plugin_version(self):
        self.assertIsNotNone(self.plugin.version)

    def test_validate_always_returns_true(self):
        """Browser plugin accepts any path per Rule 14."""
        valid, msg = self.plugin.validate_file('/nonexistent/path')
        self.assertTrue(valid)

    def test_missing_chrome_returns_not_found(self):
        """Rule 14: missing profile must not crash — return 'not_found' status."""
        from plugins.network.browser_plugin import _extract_chromium_artifacts
        result = _extract_chromium_artifacts(None, 'Google Chrome')
        self.assertEqual(result['status'], 'not_found')
        self.assertIn('history', result)
        self.assertIn('cookies', result)

    def test_missing_firefox_returns_not_found(self):
        """Rule 14: missing Firefox profile must not crash."""
        from plugins.network.browser_plugin import _extract_firefox_artifacts
        result = _extract_firefox_artifacts(None)
        self.assertEqual(result['status'], 'not_found')
        self.assertIn('history', result)
        self.assertIn('cookies', result)

    def test_missing_edge_returns_not_found(self):
        """Rule 14: missing Edge profile must not crash."""
        from plugins.network.browser_plugin import _extract_chromium_artifacts
        result = _extract_chromium_artifacts(None, 'Microsoft Edge')
        self.assertEqual(result['status'], 'not_found')

    def test_summary_always_present(self):
        """Summary dict must always be present, even with no browsers."""
        result = self.plugin.analyze(
            '.',
            browsers=[],
            profile_paths={}
        )
        self.assertIn('summary', result)

    def test_report_file_saved(self):
        """JSON report must be saved to output_dir."""
        result = self.plugin.analyze(
            '.',
            output_dir=self.temp_dir,
            profile_paths={
                'chrome': '/nonexistent',
                'firefox': '/nonexistent',
                'edge': '/nonexistent',
                'brave': '/nonexistent'
            }
        )
        self.assertIn('report_file', result)
        self.assertTrue(os.path.isfile(result['report_file']))

    def test_result_structure(self):
        """All required keys must exist in result."""
        result = self.plugin.analyze('.', profile_paths={
            'chrome': '/nonexistent', 'firefox': '/nonexistent',
            'edge': '/nonexistent', 'brave': '/nonexistent'
        })
        self.assertIn('chrome', result)
        self.assertIn('firefox', result)
        self.assertIn('edge', result)
        self.assertIn('summary', result)
        self.assertIn('scan_timestamp', result)


# =============================================================================
# EXIF METADATA PLUGIN TESTS
# =============================================================================

class TestExifMetadataPlugin(unittest.TestCase):
    """Tests for plugins/metadata/exif_plugin.py"""

    def setUp(self):
        from plugins.metadata.exif_plugin import MetadataExtractorPlugin
        self.plugin = MetadataExtractorPlugin()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_test_jpeg(self):
        """Create a minimal valid JPEG using Pillow."""
        try:
            from PIL import Image
            path = os.path.join(self.temp_dir, 'test.jpg')
            img = Image.new('RGB', (100, 100), color=(255, 0, 0))
            img.save(path, 'JPEG')
            return path
        except Exception:
            return None

    def test_plugin_name(self):
        self.assertEqual(self.plugin.name, 'Metadata Extractor')

    def test_supported_types_includes_jpeg(self):
        self.assertIn('.jpg', self.plugin.supported_types())
        self.assertIn('.jpeg', self.plugin.supported_types())

    def test_analyze_returns_file_info(self):
        path = self._create_test_jpeg()
        if path is None:
            self.skipTest('Pillow not available to create test JPEG')
        result = self.plugin.analyze(path)
        self.assertIn('file_info', result)
        self.assertEqual(result['file_info']['filename'], 'test.jpg')

    def test_analyze_nonexistent_warns(self):
        """Analyzing a missing file should add a warning, not crash."""
        path = os.path.join(self.temp_dir, 'ghost.jpg')
        # Create empty file so validate_file passes, but open will warn
        with open(path, 'wb') as f:
            f.write(b'')
        result = self.plugin.analyze(path)
        # Should still return a result dict
        self.assertIsInstance(result, dict)


# =============================================================================
# MEMORY, MOBILE & STEGO PLUGIN TESTS
# =============================================================================

class TestMemoryForensicsPlugin(unittest.TestCase):
    def setUp(self):
        from plugins.memory.volatility_plugin import MemoryForensicsPlugin
        self.plugin = MemoryForensicsPlugin()
        self.temp_dir = tempfile.mkdtemp()
        self.mem_file = os.path.join(self.temp_dir, 'sample_mem.raw')
        with open(self.mem_file, 'wb') as f:
            f.write(b'RAM_DATA_svchost.exe_192.168.1.50:443_lsass.exe_END')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_plugin_name(self):
        self.assertEqual(self.plugin.name, 'RAM Memory Analyzer')

    def test_analyze_memory_file(self):
        res = self.plugin.analyze(self.mem_file)
        self.assertIn('summary', res)
        self.assertGreater(len(res['processes_found']), 0)


class TestMobileArtifactPlugin(unittest.TestCase):
    def setUp(self):
        from plugins.mobile.mobile_plugin import MobileArtifactPlugin
        self.plugin = MobileArtifactPlugin()
        self.temp_dir = tempfile.mkdtemp()
        self.mob_file = os.path.join(self.temp_dir, 'mobile_backup.tar')
        with open(self.mob_file, 'wb') as f:
            f.write(b'MOBILE_BACKUP_DATA')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_plugin_name(self):
        self.assertEqual(self.plugin.name, 'Mobile Artifact Extractor')

    def test_analyze_mobile_file(self):
        res = self.plugin.analyze(self.mob_file)
        self.assertIn('summary', res)
        self.assertGreater(len(res['sms_messages']), 0)


class TestSteganographyDetectorPlugin(unittest.TestCase):
    def setUp(self):
        from plugins.stego.stego_plugin import SteganographyDetectorPlugin
        self.plugin = SteganographyDetectorPlugin()
        self.temp_dir = tempfile.mkdtemp()
        self.stego_file = os.path.join(self.temp_dir, 'stego.png')
        with open(self.stego_file, 'wb') as f:
            f.write(b'PNG_DATA_FLAG{STEGO_HIDDEN_PAYLOAD_DETECTED_2026}_END')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_plugin_name(self):
        self.assertEqual(self.plugin.name, 'Steganography Detector')

    def test_analyze_stego_file(self):
        res = self.plugin.analyze(self.stego_file)
        self.assertIn('stego_detected', res)
        self.assertTrue(res['stego_detected'])


# =============================================================================
# MAIN TEST RUNNER
# =============================================================================

if __name__ == '__main__':
    print('=' * 60)
    print('  ForenSync Plugin Test Suite')
    print('=' * 60)
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestHashVerifierPlugin))
    suite.addTests(loader.loadTestsFromTestCase(TestFileCarvingPlugin))
    suite.addTests(loader.loadTestsFromTestCase(TestBrowserArtifactPlugin))
    suite.addTests(loader.loadTestsFromTestCase(TestExifMetadataPlugin))
    suite.addTests(loader.loadTestsFromTestCase(TestMemoryForensicsPlugin))
    suite.addTests(loader.loadTestsFromTestCase(TestMobileArtifactPlugin))
    suite.addTests(loader.loadTestsFromTestCase(TestSteganographyDetectorPlugin))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    if result.wasSuccessful():
        print('\n[PASS] All tests passed.')
    else:
        print('\n[FAIL] Some tests failed. See output above.')
        sys.exit(1)

