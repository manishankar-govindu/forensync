# exif_plugin.py - Extracts EXIF metadata from images

import os
import json
from datetime import datetime
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import sys

# Add parent to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from backend.core.plugin_manager import ForensicPlugin
#sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))
#from core.plugin_manager import ForensicPlugin
#sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend', 'core'))
#from plugin_manager import ForensicPlugin

class MetadataExtractorPlugin(ForensicPlugin):
    """
    Extracts hidden metadata from image files including EXIF data,
    GPS coordinates, camera information, and timestamps.
    """
    
    @property
    def name(self):
        return "Metadata Extractor"
    
    @property
    def description(self):
        return "Extracts EXIF metadata, GPS coordinates, and hidden information from images"
    
    @property
    def version(self):
        return "1.0.0"
    
    def supported_types(self):
        return ['.jpg', '.jpeg', '.tiff', '.tif', '.png', '.gif', '.bmp', '.webp']
    
    def analyze(self, file_path, output_dir=None, **kwargs):
        """
        Analyze image file and extract all metadata
        """
        results = {
            'file_info': {},
            'exif_data': {},
            'gps_data': None,
            'timestamps': [],
            'camera_info': {},
            'warnings': []
        }
        
        # Basic file information
        file_stats = os.stat(file_path)
        results['file_info'] = {
            'filename': os.path.basename(file_path),
            'path': file_path,
            'size_bytes': file_stats.st_size,
            'size_human': self._format_bytes(file_stats.st_size),
            'modified_time': datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
            'accessed_time': datetime.fromtimestamp(file_stats.st_atime).isoformat(),
            'created_time': datetime.fromtimestamp(file_stats.st_ctime).isoformat()
        }
        
        # Add to timestamps
        results['timestamps'].append({
            'type': 'file_system_modified',
            'timestamp': results['file_info']['modified_time'],
            'description': 'File last modified (filesystem)'
        })
        
        # Extract EXIF data
        try:
            with Image.open(file_path) as img:
                results['file_info']['format'] = img.format
                results['file_info']['mode'] = img.mode
                results['file_info']['width'] = img.width
                results['file_info']['height'] = img.height

                # Use public getexif() (Pillow 6+) with fallback to private _getexif()
                exif_data = None
                if hasattr(img, 'getexif'):
                    # Public API: returns an Exif object (dict-like)
                    exif_obj = img.getexif()
                    exif_data = dict(exif_obj) if exif_obj else None
                elif hasattr(img, '_getexif'):
                    # Fallback for older Pillow versions (JPEG only)
                    exif_data = img._getexif()

                if exif_data:
                    results['exif_data'] = self._parse_exif(exif_data)

                    # Extract GPS if present
                    if 'GPSInfo' in results['exif_data']:
                        results['gps_data'] = self._extract_gps(results['exif_data']['GPSInfo'])

                    # Extract camera info
                    results['camera_info'] = self._extract_camera_info(results['exif_data'])

                    # Extract timestamps from EXIF
                    results['timestamps'].extend(self._extract_timestamps(results['exif_data']))

                else:
                    results['warnings'].append('No EXIF data found in image')

        except Exception as e:
            results['warnings'].append('Error reading image: {0}'.format(str(e)))
        
        # Save to file if output directory provided
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(
                output_dir, 
                f"metadata_{os.path.basename(file_path)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            results['output_file'] = output_file
        
        return results
    
    def _parse_exif(self, exif_data):
        """Convert EXIF tags to readable format"""
        parsed = {}
        
        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, tag_id)
            
            # Handle different data types
            if isinstance(value, bytes):
                try:
                    value = value.decode('utf-8', errors='ignore')
                except:
                    value = value.hex()
            elif isinstance(value, tuple) and len(value) == 2:
                # Rational numbers (like GPS coordinates)
                value = float(value[0]) / float(value[1])
            
            parsed[tag] = str(value)
        
        return parsed
    
    def _extract_gps(self, gps_info):
        """Extract GPS coordinates from EXIF GPSInfo"""
        try:
            def convert_to_degrees(value):
                """Convert GPS coordinates to decimal degrees"""
                d = float(value[0][0]) / float(value[0][1])
                m = float(value[1][0]) / float(value[1][1])
                s = float(value[2][0]) / float(value[2][1])
                return d + (m / 60.0) + (s / 3600.0)
            
            lat = convert_to_degrees(gps_info[2])  # GPSLatitude
            lat_ref = gps_info[1]  # GPSLatitudeRef
            
            lon = convert_to_degrees(gps_info[4])  # GPSLongitude
            lon_ref = gps_info[3]  # GPSLongitudeRef
            
            # Apply reference directions
            if lat_ref != 'N':
                lat = -lat
            if lon_ref != 'E':
                lon = -lon
            
            # Try to get altitude
            alt = None
            if 6 in gps_info:
                alt = float(gps_info[6][0]) / float(gps_info[6][1])
            
            return {
                'latitude': round(lat, 6),
                'longitude': round(lon, 6),
                'altitude': round(alt, 2) if alt else None,
                'google_maps_url': f"https://www.google.com/maps?q={lat},{lon}",
                'coordinates_format': f"{abs(lat):.6f}° {'N' if lat >= 0 else 'S'}, {abs(lon):.6f}° {'E' if lon >= 0 else 'W'}"
            }
            
        except Exception as e:
            return {'error': f'Failed to parse GPS: {str(e)}'}
    
    def _extract_camera_info(self, exif_data):
        """Extract camera and software information"""
        camera_fields = {
            'Make': 'manufacturer',
            'Model': 'model',
            'Software': 'software',
            'LensModel': 'lens',
            'BodySerialNumber': 'serial_number',
            'LensSerialNumber': 'lens_serial'
        }
        
        info = {}
        for exif_tag, friendly_name in camera_fields.items():
            if exif_tag in exif_data:
                info[friendly_name] = exif_data[exif_tag]
        
        return info
    
    def _extract_timestamps(self, exif_data):
        """Extract all timestamps from EXIF data"""
        timestamp_tags = {
            'DateTime': 'Image modification',
            'DateTimeOriginal': 'Photo taken (original)',
            'DateTimeDigitized': 'Photo digitized',
            'GPSDateStamp': 'GPS date',
            'GPSTimeStamp': 'GPS time'
        }
        
        timestamps = []
        for tag, description in timestamp_tags.items():
            if tag in exif_data:
                timestamps.append({
                    'type': tag,
                    'description': description,
                    'timestamp': exif_data[tag]
                })
        
        return timestamps
    
    def _format_bytes(self, size):
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"

# For testing the plugin directly
if __name__ == '__main__':
    # Test with a sample image
    plugin = MetadataExtractorPlugin()
    print(f"Plugin: {plugin.name} v{plugin.version}")
    print(f"Description: {plugin.description}")
    print(f"Supported types: {plugin.supported_types()}")
    
    # If you have a test image, uncomment below:
    # result = plugin.analyze('path/to/test/image.jpg', './test_output')
    # print(json.dumps(result, indent=2))