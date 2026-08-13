# hash_plugin.py - Verifies file integrity using multiple hash algorithms

import os
import hashlib
import json
from datetime import datetime
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from backend.core.plugin_manager import ForensicPlugin

class HashVerifierPlugin(ForensicPlugin):
    """
    Calculates and verifies multiple hash types for forensic integrity.
    Supports MD5, SHA1, SHA256, SHA512.
    """
    
    @property
    def name(self):
        return "Hash Verifier"
    
    @property
    def description(self):
        return "Calculates MD5, SHA1, SHA256, SHA512 hashes for file integrity verification"
    
    @property
    def version(self):
        return "1.0.0"
    
    def supported_types(self):
        # Supports all file types
        return ['.*']

    def validate_file(self, file_path):
        """Hash verifier works on any file — override to skip extension check."""
        if not os.path.exists(file_path):
            return False, "File does not exist"
        if os.path.isdir(file_path):
            return False, "Path is a directory, not a file"
        return True, "Valid"
    
    def analyze(self, file_path, output_dir=None, **kwargs):
        """
        Calculate multiple hashes for a file
        """
        results = {
            'file_info': {},
            'hashes': {},
            'verification': None,
            'entropy': None
        }
        
        # File information
        file_stats = os.stat(file_path)
        results['file_info'] = {
            'filename': os.path.basename(file_path),
            'path': file_path,
            'size_bytes': file_stats.st_size,
            'size_human': self._format_bytes(file_stats.st_size)
        }
        
        # Calculate hashes
        hash_algorithms = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha512': hashlib.sha512()
        }
        
        print(f"Calculating hashes for: {os.path.basename(file_path)}")
        
        # Read file and update all hashes simultaneously
        bytes_read = 0
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(8192)  # Read in 8KB chunks
                if not chunk:
                    break
                
                for hash_obj in hash_algorithms.values():
                    hash_obj.update(chunk)
                
                bytes_read += len(chunk)
                
                # Progress indicator for large files
                if bytes_read % (10 * 1024 * 1024) == 0:  # Every 10MB
                    print(f"  Processed: {self._format_bytes(bytes_read)}")
        
        # Get hex digests
        for name, hash_obj in hash_algorithms.items():
            results['hashes'][name] = hash_obj.hexdigest()
        
        # Calculate file entropy (randomness indicator)
        results['entropy'] = self._calculate_entropy(file_path)
        
        # If user provided expected hash, verify it
        expected_hash = kwargs.get('expected_hash')
        if expected_hash:
            results['verification'] = self._verify_hash(results['hashes'], expected_hash)
        
        # Save results
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(
                output_dir,
                f"hashes_{os.path.basename(file_path)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            results['output_file'] = output_file
        
        return results
    
    def _calculate_entropy(self, file_path):
        """
        Calculate Shannon entropy of file (0-8 scale).
        High entropy (>7.5) suggests encryption or compression.
        Uses collections.Counter for a single-pass O(n) calculation.
        """
        try:
            from collections import Counter
            from math import log2

            with open(file_path, 'rb') as f:
                data = f.read()

            if not data:
                return 0.0

            counts = Counter(data)  # data is a bytes object; iterating gives integers
            length = len(data)
            entropy = 0.0
            for count in counts.values():
                p_x = count / length
                entropy -= p_x * log2(p_x)

            return round(entropy, 4)

        except Exception as e:
            return 'Error: {0}'.format(str(e))
    
    def _verify_hash(self, calculated_hashes, expected_hash):
        """Verify if expected hash matches any calculated hash"""
        expected = expected_hash.lower().strip()
        
        for hash_type, hash_value in calculated_hashes.items():
            if hash_value.lower() == expected:
                return {
                    'match': True,
                    'matched_algorithm': hash_type,
                    'message': f'Hash verified using {hash_type.upper()}'
                }
        
        return {
            'match': False,
            'message': 'No matching hash found. File may be corrupted or tampered with.',
            'suspicious': True
        }
    
    def _format_bytes(self, size):
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"

# Test
if __name__ == '__main__':
    plugin = HashVerifierPlugin()
    print(f"Plugin: {plugin.name}")
    print(f"Testing with current file...")
    result = plugin.analyze(__file__, './test_output')
    print(json.dumps(result, indent=2))