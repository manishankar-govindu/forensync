# autopsy_plugin.py - Autopsy Integration Plugin for ForenSync
# Simulates Autopsy forensic disk analysis: file hashing, archive unpacking, metadata extraction,
# contact/email parsing, database carving, registry analysis, keyword indexing, and USB device detection.

import os
import sys
import json
import hashlib
import sqlite3
import zipfile
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from backend.core.plugin_manager import ForensicPlugin


class AutopsyIntegrationPlugin(ForensicPlugin):

    @property
    def name(self):
        return "Autopsy Disk Analyzer"

    @property
    def description(self):
        return "Integrates Autopsy-like disk analysis: file hashing, archive extraction, metadata indexing, contact/email parsing, database analysis, and USB device history detection."

    @property
    def version(self):
        return "1.0.0"

    def supported_types(self):
        return ['.dd', '.raw', '.img', '.bin', '.vmdk', '.vhd', '.tar', '.zip', '']

    def validate_file(self, file_path):
        if not os.path.exists(file_path):
            return False, "Path does not exist"
        return True, "Valid"

    def analyze(self, file_path, output_dir=None, **kwargs):
        results = {
            'source': os.path.basename(file_path),
            'scan_type': 'directory' if os.path.isdir(file_path) else 'disk_image',
            'file_hashes': [],
            'extracted_archives': [],
            'metadata_indexed': [],
            'contacts_extracted': [],
            'emails_found': [],
            'databases_analyzed': [],
            'registry_entries': [],
            'usb_device_history': [],
            'keywords_indexed': [],
            'summary': {},
            'timestamp': datetime.now().isoformat()
        }

        # Step 1: Hash all files (SHA256, MD5)
        results['file_hashes'] = self._scan_and_hash_files(file_path)

        # Step 2: Unpack/analyze archives
        results['extracted_archives'] = self._analyze_archives(file_path)

        # Step 3: Index metadata (EXIF, file attributes)
        results['metadata_indexed'] = self._index_metadata(file_path)

        # Step 4: Extract contacts (VCF, Outlook PST simulation)
        results['contacts_extracted'] = self._extract_contacts(file_path)

        # Step 5: Find and parse emails
        results['emails_found'] = self._extract_emails(file_path)

        # Step 6: Analyze SQLite/database files
        results['databases_analyzed'] = self._analyze_databases(file_path)

        # Step 7: Simulate registry analysis (Windows-specific)
        results['registry_entries'] = self._analyze_registry(file_path)

        # Step 8: Detect USB device history
        results['usb_device_history'] = self._detect_usb_devices(file_path)

        # Step 9: Keyword indexing (common keywords)
        results['keywords_indexed'] = self._index_keywords(file_path)

        # Generate summary
        results['summary'] = {
            'total_files_hashed': len(results['file_hashes']),
            'total_archives_found': len(results['extracted_archives']),
            'total_contacts': len(results['contacts_extracted']),
            'total_emails': len(results['emails_found']),
            'total_databases': len(results['databases_analyzed']),
            'usb_devices_detected': len(results['usb_device_history']),
            'keywords_indexed': len(results['keywords_indexed'])
        }

        # Save report
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            report_file = os.path.join(output_dir, f"autopsy_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(report_file, 'w', encoding='utf-8') as rf:
                json.dump(results, rf, indent=2, default=str)
            results['report_file'] = report_file

        return results

    def _scan_and_hash_files(self, path):
        """Recursively hash all files (SHA256, MD5)"""
        hashes = []
        
        def _hash_file(fpath):
            try:
                sha256 = hashlib.sha256()
                md5 = hashlib.md5()
                with open(fpath, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b''):
                        sha256.update(chunk)
                        md5.update(chunk)
                
                hashes.append({
                    'file': os.path.relpath(fpath, path),
                    'size_bytes': os.path.getsize(fpath),
                    'sha256': sha256.hexdigest(),
                    'md5': md5.hexdigest()
                })
            except Exception:
                pass
        
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for fname in files:
                    _hash_file(os.path.join(root, fname))
                if len(hashes) >= 50:  # Limit for demo
                    break
        else:
            _hash_file(path)
        
        return hashes[:50]  # Return top 50 hashes

    def _analyze_archives(self, path):
        """Extract and analyze ZIP, TAR, etc."""
        archives = []
        
        def _process_archive(fpath):
            try:
                if zipfile.is_zipfile(fpath):
                    with zipfile.ZipFile(fpath, 'r') as zf:
                        files = zf.namelist()
                        archives.append({
                            'type': 'ZIP',
                            'source': os.path.relpath(fpath, path),
                            'file_count': len(files),
                            'files': files[:10],  # First 10 files
                            'total_size': sum(zf.getinfo(name).file_size for name in files)
                        })
            except Exception:
                pass
        
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for fname in files:
                    if fname.endswith('.zip'):
                        _process_archive(os.path.join(root, fname))
                if len(archives) >= 10:
                    break
        else:
            if path.endswith('.zip'):
                _process_archive(path)
        
        return archives

    def _index_metadata(self, path):
        """Index file metadata (EXIF simulation, timestamps)"""
        metadata = []
        
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        stat = os.stat(fpath)
                        metadata.append({
                            'file': os.path.relpath(fpath, path),
                            'size': stat.st_size,
                            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            'accessed': datetime.fromtimestamp(stat.st_atime).isoformat()
                        })
                    except Exception:
                        pass
                if len(metadata) >= 30:
                    break
        else:
            try:
                stat = os.stat(path)
                metadata.append({
                    'file': os.path.basename(path),
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'accessed': datetime.fromtimestamp(stat.st_atime).isoformat()
                })
            except Exception:
                pass
        
        return metadata

    def _extract_contacts(self, path):
        """Extract contacts (VCF, Outlook simulation)"""
        contacts = []
        
        # Simulate finding contact files
        contact_files = []
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for fname in files:
                    if fname.endswith('.vcf') or fname.endswith('.pst') or 'contacts' in fname.lower():
                        contact_files.append(os.path.join(root, fname))
        
        # Return mock data if actual files not found
        if not contact_files:
            contacts = [
                {'name': 'John Doe', 'email': 'john.doe@example.com', 'phone': '+1 555 0100', 'type': 'Personal'},
                {'name': 'Jane Smith', 'email': 'jane.smith@example.com', 'phone': '+1 555 0101', 'type': 'Work'},
                {'name': 'Suspect Person', 'email': 'suspect@suspicious.com', 'phone': '+1 555 0199', 'type': 'Unknown'},
            ]
        
        return contacts

    def _extract_emails(self, path):
        """Extract emails (PST, EML simulation)"""
        emails = []
        
        # Simulate finding email files
        email_files = []
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for fname in files:
                    if fname.endswith('.pst') or fname.endswith('.eml') or fname.endswith('.msg'):
                        email_files.append(os.path.join(root, fname))
        
        # Return mock data
        if not email_files:
            emails = [
                {'from': 'alice@company.com', 'to': 'bob@company.com', 'subject': 'Meeting Tomorrow', 'date': '2026-07-15 09:30:00', 'body_preview': 'Confirming our 2pm meeting...'},
                {'from': 'charlie@external.com', 'to': 'alice@company.com', 'subject': 'Urgent: Data Transfer', 'date': '2026-07-16 14:22:00', 'body_preview': 'FLAG{AUTOPSY_EMAIL_EXTRACTED_EVIDENCE}'},
            ]
        
        return emails

    def _analyze_databases(self, path):
        """Analyze SQLite and other database files"""
        databases = []
        
        def _analyze_db(fpath):
            try:
                if fpath.endswith('.db') or fpath.endswith('.sqlite') or fpath.endswith('.sqlite3'):
                    conn = sqlite3.connect(fpath)
                    cursor = conn.cursor()
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                    tables = [t[0] for t in cursor.fetchall()]
                    
                    databases.append({
                        'file': os.path.relpath(fpath, path),
                        'type': 'SQLite',
                        'tables': tables,
                        'table_count': len(tables)
                    })
                    conn.close()
            except Exception:
                pass
        
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for fname in files:
                    _analyze_db(os.path.join(root, fname))
                if len(databases) >= 20:
                    break
        else:
            _analyze_db(path)
        
        return databases

    def _analyze_registry(self, path):
        """Simulate Windows registry analysis (USB device detection, recent files)"""
        registry_entries = []
        
        # Mock registry findings
        if os.path.isdir(path) and 'windows' in path.lower():
            registry_entries = [
                {'hive': 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR', 'value': 'USB Storage Driver', 'data': 'Installed'},
                {'hive': 'HKEY_LOCAL_MACHINE\\SYSTEM\\MountedDevices', 'value': '\\??\\Volume{12345}', 'data': 'G:\\'},
                {'hive': 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs', 'value': 'suspicious_file.zip', 'data': '2026-07-16'},
            ]
        
        return registry_entries

    def _detect_usb_devices(self, path):
        """Detect USB device history"""
        usb_devices = []
        
        # Simulate USB device detection (would come from registry or mount logs)
        usb_devices = [
            {'device_name': 'Kingston DataTraveler 3.0', 'serial': 'ABC123DEF456', 'first_connected': '2026-07-10 10:15:30', 'last_connected': '2026-07-16 14:20:00', 'size_gb': 8},
            {'device_name': 'SanDisk Cruzer', 'serial': 'XYZ789UVW012', 'first_connected': '2026-07-01 08:00:00', 'last_connected': '2026-07-15 16:45:00', 'size_gb': 16},
        ]
        
        return usb_devices

    def _index_keywords(self, path):
        """Index common keywords (like Autopsy does)"""
        keywords = ['password', 'secret', 'confidential', 'suspect', 'evidence', 'transfer', 'delete', 'hide']
        keywords_indexed = []
        
        # Simulate finding keywords in files
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, 'r', errors='ignore') as f:
                            content = f.read(10000)  # First 10KB
                            for kw in keywords:
                                if kw.lower() in content.lower():
                                    keywords_indexed.append({
                                        'keyword': kw,
                                        'file': os.path.relpath(fpath, path),
                                        'occurrences': content.lower().count(kw.lower())
                                    })
                                    break
                    except Exception:
                        pass
                if len(keywords_indexed) >= 15:
                    break
        
        return keywords_indexed
