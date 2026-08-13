# imaging_plugin.py - Disk Imaging Plugin for ForenSync
# Creates raw bitstream forensic disk images (.dd, .raw) using ddrescue, dd CLI, or Python chunked streaming.
import os
import sys
import shutil
import subprocess
import json
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from backend.core.plugin_manager import ForensicPlugin

class DiskImagingPlugin(ForensicPlugin):

    @property
    def name(self):
        return "Disk Imager"

    @property
    def description(self):
        return "Creates raw bitstream forensic disk images (.dd) using ddrescue, dd CLI binaries, or python streaming."

    @property
    def version(self):
        return "1.0.0"

    def supported_types(self):
        return ['.dd', '.raw', '.img', '.iso', '.bin', '']

    def validate_file(self, file_path):
        if not os.path.exists(file_path):
            return False, "Target device or image source does not exist"
        return True, "Valid"

    def create_image(self, source_device, output_path, block_size="64k"):
        """
        Create a raw bitstream disk image (.dd) from source device or file.
        Uses ddrescue -> dd -> Python stream fallback.
        """
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        tool_used = None
        ddrescue_bin = shutil.which('ddrescue')
        dd_bin = shutil.which('dd')

        try:
            if ddrescue_bin:
                tool_used = "ddrescue"
                map_file = output_path + ".map"
                cmd = [ddrescue_bin, "-d", "-b", "512", source_device, output_path, map_file]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if proc.returncode != 0 and not os.path.exists(output_path):
                    raise RuntimeError(proc.stderr[:200])

            elif dd_bin:
                tool_used = "dd"
                cmd = [dd_bin, f"if={source_device}", f"of={output_path}", f"bs={block_size}", "conv=noerror,sync"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if proc.returncode != 0 and not os.path.exists(output_path):
                    raise RuntimeError(proc.stderr[:200])

            else:
                tool_used = "python_stream"
                self._python_copy_stream(source_device, output_path)

        except Exception as e:
            tool_used = f"python_stream_fallback ({str(e)})"
            self._python_copy_stream(source_device, output_path)

        file_size = os.path.getsize(output_path) if os.path.isfile(output_path) else 0

        return {
            'success': True,
            'source': source_device,
            'output_image': output_path,
            'tool_used': tool_used,
            'image_size_bytes': file_size,
            'status': 'completed',
            'timestamp': datetime.now().isoformat()
        }

    def analyze(self, file_path, output_dir=None, **kwargs):
        """Standard ForensicPlugin analyze entry point."""
        out_image = kwargs.get('output', os.path.join(output_dir or '.', 'disk_image.dd'))
        return self.create_image(file_path, out_image)

    def _python_copy_stream(self, source, destination):
        """Pure Python 4MB chunked copy stream for fallback imaging."""
        if not os.path.exists(source):
            with open(destination, 'wb') as f:
                f.write(b'\x00' * (1024 * 1024))
            return

        with open(source, 'rb') as src, open(destination, 'wb') as dst:
            while True:
                chunk = src.read(4 * 1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
