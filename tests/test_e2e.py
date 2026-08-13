# test_e2e.py - End-to-End Test Suite for ForenSync Platform
import os
import sys
import json
import unittest
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backend'))

from backend.app import app, db, init_db, User, Case, Evidence, AuditLog

class TestForenSyncE2E(unittest.TestCase):

    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['SECRET_KEY'] = 'test-secret-key'
        self.client = app.test_client()

        with app.app_context():
            init_db(app)

        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_full_investigation_workflow(self):
        # 1. Login
        res = self.client.post('/api/auth/login', json={
            'username': 'admin',
            'password': 'admin123'
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])

        # 2. Check Auth Status
        res = self.client.get('/api/auth/me')
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json()['authenticated'])

        # 3. Create Case
        res = self.client.post('/api/cases', json={
            'name': 'Cyber Heist Case 2026',
            'description': 'Investigating suspicious drive image'
        })
        self.assertEqual(res.status_code, 201)
        case_data = res.get_json()['case']
        case_id = case_data['id']
        self.assertIsNotNone(case_id)

        # 4. Upload Evidence File (containing embedded JPEG)
        test_file_path = os.path.join(self.temp_dir, 'evidence_image.bin')
        jpeg_header = bytes([0xFF, 0xD8, 0xFF, 0xE0])
        jpeg_body = b'SECURE_EV_DATA' * 10
        jpeg_footer = bytes([0xFF, 0xD9])
        with open(test_file_path, 'wb') as f:
            f.write(b'HEAD' + jpeg_header + jpeg_body + jpeg_footer + b'TAIL')

        with open(test_file_path, 'rb') as f:
            res = self.client.post('/api/upload', data={
                'case_id': case_id,
                'file': (f, 'evidence_image.bin')
            })
        self.assertEqual(res.status_code, 201)
        ev_data = res.get_json()['evidence']
        ev_id = ev_data['id']
        self.assertEqual(ev_data['original_filename'], 'evidence_image.bin')
        self.assertIsNotNone(ev_data['md5_hash'])

        # 5. List Evidence for Case
        res = self.client.get(f'/api/cases/{case_id}/evidence')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()['total'], 1)

        # 6. Run File Carver
        res = self.client.post('/api/carve', json={'evidence_id': ev_id})
        self.assertEqual(res.status_code, 200)
        carve_res = res.get_json()
        self.assertTrue(carve_res['success'])
        self.assertGreater(len(carve_res['results']['carved_files']), 0)

        # 7. Run Hash Verifier Plugin
        res = self.client.post('/api/analyze', json={
            'evidence_id': ev_id,
            'plugin_name': 'Hash Verifier'
        })
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json()['success'])

        # 8. Generate HTML Report
        res = self.client.get(f'/api/cases/{case_id}/report')
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json()['success'])

        # 9. Generate PDF Report
        res = self.client.get(f'/api/cases/{case_id}/report/pdf')
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json()['success'])

        # 10. Generate JSON Report
        res = self.client.get(f'/api/cases/{case_id}/report/json')
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json()['success'])

        # 11. Test Async Background Worker Carving Queue
        res = self.client.post('/api/carve', json={'evidence_id': ev_id, 'async': True})
        self.assertEqual(res.status_code, 200)
        async_data = res.get_json()
        self.assertTrue(async_data['success'])
        self.assertTrue(async_data['async'])
        task_id = async_data['task_id']

        # Poll task status
        res = self.client.get(f'/api/carve/status/{task_id}')
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json()['success'])

        # 12. Test Subprocess CLI Execution Route (with graceful fallback)
        res = self.client.post('/api/tools/run-cli', json={'tool': 'foremost', 'target_file': test_file_path})
        self.assertEqual(res.status_code, 200)
        self.assertIn('cli_available', res.get_json())

        # 13. Verify Audit Logs
        res = self.client.get('/api/audit-log')
        self.assertEqual(res.status_code, 200)
        logs = res.get_json()['logs']
        self.assertGreater(len(logs), 0)

if __name__ == '__main__':
    unittest.main()
