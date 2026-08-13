# browser_plugin.py - Browser Artifact Extractor for ForenSync
# Extracts forensic artifacts from Chrome, Edge, Brave, and Firefox browser profiles & SQLite databases.
import os
import sys
import json
import sqlite3
import shutil
import platform
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from backend.core.plugin_manager import ForensicPlugin


# =============================================================================
# SQLITE VALIDATION HELPER
# =============================================================================

def is_sqlite_file(file_path):
    """Check if file exists and starts with 16-byte SQLite header magic bytes."""
    try:
        if not os.path.isfile(file_path):
            return False
        with open(file_path, 'rb') as f:
            return f.read(16).startswith(b'SQLite format 3')
    except Exception:
        return False


# =============================================================================
# PLATFORM DETECTION & PROFILE RESOLVERS
# =============================================================================

def _get_platform():
    """Return a normalized platform identifier: 'windows', 'darwin', or 'linux'."""
    system = platform.system()
    if system == 'Windows':
        return 'windows'
    elif system == 'Darwin':
        return 'darwin'
    return 'linux'


def _get_chrome_profile_path():
    """Return default Chrome profile path for the current OS, or None."""
    plat = _get_platform()
    home = os.path.expanduser('~')
    if plat == 'windows':
        path = os.path.join(home, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default')
    elif plat == 'darwin':
        path = os.path.join(home, 'Library', 'Application Support', 'Google', 'Chrome', 'Default')
    else:
        path = os.path.join(home, '.config', 'google-chrome', 'Default')
    return path if os.path.isdir(path) else None


def _get_edge_profile_path():
    """Return default Edge profile path for the current OS, or None."""
    plat = _get_platform()
    home = os.path.expanduser('~')
    if plat == 'windows':
        path = os.path.join(home, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default')
    elif plat == 'darwin':
        path = os.path.join(home, 'Library', 'Application Support', 'Microsoft Edge', 'Default')
    else:
        path = os.path.join(home, '.config', 'microsoft-edge', 'Default')
    return path if os.path.isdir(path) else None


def _get_brave_profile_path():
    """Return default Brave profile path for the current OS, or None."""
    plat = _get_platform()
    home = os.path.expanduser('~')
    if plat == 'windows':
        path = os.path.join(home, 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default')
    elif plat == 'darwin':
        path = os.path.join(home, 'Library', 'Application Support', 'BraveSoftware', 'Brave-Browser', 'Default')
    else:
        path = os.path.join(home, '.config', 'BraveSoftware', 'Brave-Browser', 'Default')
    return path if os.path.isdir(path) else None


def _get_firefox_profile_path():
    """Return path to the first Firefox profile directory found, or None."""
    plat = _get_platform()
    home = os.path.expanduser('~')
    if plat == 'windows':
        profiles_root = os.path.join(home, 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles')
    elif plat == 'darwin':
        profiles_root = os.path.join(home, 'Library', 'Application Support', 'Firefox', 'Profiles')
    else:
        profiles_root = os.path.join(home, '.mozilla', 'firefox')

    if not os.path.isdir(profiles_root):
        return None

    entries = [
        e for e in os.listdir(profiles_root)
        if os.path.isdir(os.path.join(profiles_root, e))
    ]
    for entry in entries:
        if 'default' in entry.lower():
            return os.path.join(profiles_root, entry)
    return os.path.join(profiles_root, entries[0]) if entries else None


# =============================================================================
# SAFE SQLITE QUERY EXECUTION
# =============================================================================

def _safe_sqlite_query(db_path, query, params=()):
    """Execute a query against a copy of a SQLite DB to avoid file locks."""
    if not os.path.isfile(db_path):
        return [], 'File not found'

    tmp_path = db_path + '.tmp_forensync'
    try:
        shutil.copy2(db_path, tmp_path)
        conn = sqlite3.connect(tmp_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows, None
    except Exception as e:
        return [], str(e)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


# =============================================================================
# TIMESTAMP CONVERTERS
# =============================================================================

def _chrome_ts_to_iso(chrome_ts):
    """Convert Chrome timestamp (microseconds since 1601-01-01) to ISO string."""
    if not chrome_ts or chrome_ts == 0:
        return None
    try:
        unix_ts = (int(chrome_ts) / 1000000.0) - 11644473600.0
        return datetime.fromtimestamp(unix_ts).isoformat()
    except Exception:
        return str(chrome_ts)


def _firefox_ts_to_iso(firefox_ts):
    """Convert Firefox timestamp (microseconds since Unix epoch) to ISO string."""
    if not firefox_ts or firefox_ts == 0:
        return None
    try:
        return datetime.fromtimestamp(int(firefox_ts) / 1000000.0).isoformat()
    except Exception:
        return str(firefox_ts)


def _format_bytes(size):
    """Convert bytes to human-readable string."""
    if not size:
        return '0 B'
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"


# =============================================================================
# CHROMIUM & FIREFOX PROFILE EXTRACTORS
# =============================================================================

def _extract_chromium_artifacts(profile_path, browser_name):
    """Extract history, downloads, and cookies from a Chromium profile folder."""
    if not profile_path or not os.path.isdir(profile_path):
        return {
            'status': 'not_found',
            'message': f"{browser_name} profile folder was not found on this system.",
            'profile_path': profile_path,
            'history': [],
            'downloads': [],
            'cookies': [],
            'errors': []
        }

    result = {
        'status': 'success',
        'browser': browser_name,
        'profile_path': profile_path,
        'history': [],
        'downloads': [],
        'cookies': [],
        'errors': []
    }

    history_db = os.path.join(profile_path, 'History')
    if os.path.isfile(history_db):
        rows, err = _safe_sqlite_query(
            history_db,
            'SELECT url, title, visit_count, last_visit_time, typed_count FROM urls ORDER BY last_visit_time DESC LIMIT 1000'
        )
        if not err:
            for row in rows:
                result['history'].append({
                    'url': row.get('url', ''),
                    'title': row.get('title', ''),
                    'visit_count': row.get('visit_count', 0),
                    'last_visit': _chrome_ts_to_iso(row.get('last_visit_time', 0)),
                    'manually_typed': row.get('typed_count', 0) > 0
                })

        dl_rows, dl_err = _safe_sqlite_query(
            history_db,
            'SELECT target_path, tab_url, total_bytes, start_time, end_time, state FROM downloads ORDER BY start_time DESC LIMIT 500'
        )
        if not dl_err:
            state_map = {0: 'in_progress', 1: 'complete', 2: 'cancelled', 3: 'interrupted'}
            for row in dl_rows:
                result['downloads'].append({
                    'filename': os.path.basename(str(row.get('target_path', ''))),
                    'full_path': row.get('target_path', ''),
                    'source_url': row.get('tab_url', ''),
                    'size_bytes': row.get('total_bytes', 0),
                    'size_human': _format_bytes(row.get('total_bytes', 0)),
                    'start_time': _chrome_ts_to_iso(row.get('start_time', 0)),
                    'end_time': _chrome_ts_to_iso(row.get('end_time', 0)),
                    'state': state_map.get(row.get('state', -1), 'unknown')
                })

    cookies_db = os.path.join(profile_path, 'Network', 'Cookies')
    if not os.path.isfile(cookies_db):
        cookies_db = os.path.join(profile_path, 'Cookies')

    if os.path.isfile(cookies_db):
        c_rows, c_err = _safe_sqlite_query(
            cookies_db,
            'SELECT host_key, name, path, expires_utc, creation_utc, is_secure, is_httponly FROM cookies ORDER BY creation_utc DESC LIMIT 1000'
        )
        if not c_err:
            for row in c_rows:
                result['cookies'].append({
                    'host': row.get('host_key', ''),
                    'name': row.get('name', ''),
                    'path': row.get('path', ''),
                    'expires': _chrome_ts_to_iso(row.get('expires_utc', 0)),
                    'created': _chrome_ts_to_iso(row.get('creation_utc', 0)),
                    'secure': bool(row.get('is_secure', 0)),
                    'http_only': bool(row.get('is_httponly', 0))
                })

    return result


def _extract_firefox_artifacts(profile_path):
    """Extract history, downloads, and cookies from a Firefox profile folder."""
    if not profile_path or not os.path.isdir(profile_path):
        return {
            'status': 'not_found',
            'message': 'Firefox profile folder was not found on this system.',
            'profile_path': profile_path,
            'history': [],
            'downloads': [],
            'cookies': [],
            'errors': []
        }

    result = {
        'status': 'success',
        'browser': 'Mozilla Firefox',
        'profile_path': profile_path,
        'history': [],
        'downloads': [],
        'cookies': [],
        'errors': []
    }

    places_db = os.path.join(profile_path, 'places.sqlite')
    if os.path.isfile(places_db):
        rows, err = _safe_sqlite_query(
            places_db,
            'SELECT url, title, visit_count, last_visit_date, typed FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 1000'
        )
        if not err:
            for row in rows:
                result['history'].append({
                    'url': row.get('url', ''),
                    'title': row.get('title', ''),
                    'visit_count': row.get('visit_count', 0),
                    'last_visit': _firefox_ts_to_iso(row.get('last_visit_date', 0)),
                    'manually_typed': bool(row.get('typed', 0))
                })

    cookies_db = os.path.join(profile_path, 'cookies.sqlite')
    if os.path.isfile(cookies_db):
        c_rows, c_err = _safe_sqlite_query(
            cookies_db,
            'SELECT host, name, path, expiry, creationTime, isSecure, isHttpOnly FROM moz_cookies ORDER BY creationTime DESC LIMIT 1000'
        )
        if not c_err:
            for row in c_rows:
                result['cookies'].append({
                    'host': row.get('host', ''),
                    'name': row.get('name', ''),
                    'path': row.get('path', ''),
                    'expires': str(row.get('expiry', '')),
                    'created': str(row.get('creationTime', '')),
                    'secure': bool(row.get('isSecure', 0)),
                    'http_only': bool(row.get('isHttpOnly', 0))
                })

    return result


# =============================================================================
# DIRECT EVIDENTIARY SQLITE DATABASE PARSER
# =============================================================================

def _extract_direct_sqlite_db(file_path):
    """
    Directly parse a single uploaded SQLite database file (History, cookies.sqlite, places.sqlite).
    Validates table presence to ensure it's a real browser database.
    """
    if not is_sqlite_file(file_path):
        return {
            'success': False,
            'error': 'Requires browser profile database (SQLite format)',
            'target_file': os.path.basename(file_path)
        }

    history = []
    cookies = []
    downloads = []
    errors = []

    # 1. Query tables present
    table_rows, err = _safe_sqlite_query(file_path, "SELECT name FROM sqlite_master WHERE type='table';")
    if err:
        return {'success': False, 'error': f"Failed to read SQLite database tables: {err}"}

    table_names = [r['name'].lower() for r in table_rows]

    # Check for Chromium urls/downloads/cookies tables
    if 'urls' in table_names:
        u_rows, _ = _safe_sqlite_query(file_path, 'SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 1000')
        for r in u_rows:
            history.append({
                'url': r.get('url', ''),
                'title': r.get('title', ''),
                'visit_count': r.get('visit_count', 0),
                'last_visit': _chrome_ts_to_iso(r.get('last_visit_time', 0))
            })

    if 'downloads' in table_names:
        d_rows, _ = _safe_sqlite_query(file_path, 'SELECT target_path, tab_url, total_bytes, start_time FROM downloads ORDER BY start_time DESC LIMIT 500')
        for r in d_rows:
            downloads.append({
                'filename': os.path.basename(str(r.get('target_path', ''))),
                'full_path': r.get('target_path', ''),
                'source_url': r.get('tab_url', ''),
                'size_bytes': r.get('total_bytes', 0),
                'size_human': _format_bytes(r.get('total_bytes', 0)),
                'start_time': _chrome_ts_to_iso(r.get('start_time', 0))
            })

    if 'cookies' in table_names:
        c_rows, _ = _safe_sqlite_query(file_path, 'SELECT host_key, name, path, expires_utc FROM cookies ORDER BY creation_utc DESC LIMIT 1000')
        for r in c_rows:
            cookies.append({
                'host': r.get('host_key', ''),
                'name': r.get('name', ''),
                'path': r.get('path', ''),
                'expires': _chrome_ts_to_iso(r.get('expires_utc', 0))
            })

    # Check for Firefox places/cookies tables
    if 'moz_places' in table_names:
        fp_rows, _ = _safe_sqlite_query(file_path, 'SELECT url, title, visit_count, last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 1000')
        for r in fp_rows:
            history.append({
                'url': r.get('url', ''),
                'title': r.get('title', ''),
                'visit_count': r.get('visit_count', 0),
                'last_visit': _firefox_ts_to_iso(r.get('last_visit_date', 0))
            })

    if 'moz_cookies' in table_names:
        fc_rows, _ = _safe_sqlite_query(file_path, 'SELECT host, name, path, expiry FROM moz_cookies ORDER BY creationTime DESC LIMIT 1000')
        for r in fc_rows:
            cookies.append({
                'host': r.get('host', ''),
                'name': r.get('name', ''),
                'path': r.get('path', ''),
                'expires': str(r.get('expiry', ''))
            })

    # If no recognized browser tables were present or 0 records found
    total = len(history) + len(cookies) + len(downloads)
    if total == 0:
        return {
            'success': True,
            'message': 'No browser artifacts found',
            'target_file': os.path.basename(file_path),
            'chrome': {'status': 'no_artifacts', 'history': [], 'cookies': [], 'downloads': []},
            'firefox': {'status': 'no_artifacts', 'history': [], 'cookies': [], 'downloads': []},
            'edge': {'status': 'no_artifacts', 'history': [], 'cookies': [], 'downloads': []},
            'brave': {'status': 'no_artifacts', 'history': [], 'cookies': [], 'downloads': []},
            'summary': {
                'browsers_found': [],
                'total_history_entries': 0,
                'total_cookies': 0,
                'total_downloads': 0,
                'total_artifacts': 0
            },
            'scan_timestamp': datetime.now().isoformat()
        }

    parsed_res = {
        'status': 'success',
        'history': history,
        'cookies': cookies,
        'downloads': downloads,
        'errors': errors
    }

    return {
        'success': True,
        'target_file': os.path.basename(file_path),
        'chrome': parsed_res,
        'firefox': {'status': 'not_found', 'history': [], 'cookies': [], 'downloads': []},
        'edge': {'status': 'not_found', 'history': [], 'cookies': [], 'downloads': []},
        'brave': {'status': 'not_found', 'history': [], 'cookies': [], 'downloads': []},
        'summary': {
            'browsers_found': ['direct_sqlite_upload'],
            'total_history_entries': len(history),
            'total_cookies': len(cookies),
            'total_downloads': len(downloads),
            'total_artifacts': total
        },
        'scan_timestamp': datetime.now().isoformat()
    }


# =============================================================================
# PLUGIN CLASS
# =============================================================================

class BrowserArtifactPlugin(ForensicPlugin):

    @property
    def name(self):
        return "Browser Artifact Extractor"

    @property
    def description(self):
        return (
            "Extracts browsing history, downloads, and cookies from "
            "Chrome, Edge, Brave, and Firefox SQLite database files or system profiles."
        )

    @property
    def version(self):
        return "1.1.0"

    def supported_types(self):
        return ['.sqlite', '.db', '']

    def validate_file(self, file_path):
        """Validate if target path is a valid SQLite file or scanner path."""
        if os.path.isfile(file_path) and file_path != '.':
            if not is_sqlite_file(file_path):
                return False, "Requires browser profile database (SQLite format)"
        return True, "Valid"

    def analyze(self, file_path, output_dir=None, **kwargs):
        """
        Extract browser artifacts from uploaded evidence file or system profile paths.
        """
        # Scenario A: Target file is a specific single uploaded file (not '.' or folder)
        if file_path and os.path.isfile(file_path) and file_path != '.':
            if not is_sqlite_file(file_path):
                return {
                    'success': False,
                    'error': 'Requires browser profile database (SQLite format)',
                    'target_file': os.path.basename(file_path),
                    'chrome': {'status': 'invalid_format', 'history': [], 'cookies': [], 'downloads': []},
                    'firefox': {'status': 'invalid_format', 'history': [], 'cookies': [], 'downloads': []},
                    'edge': {'status': 'invalid_format', 'history': [], 'cookies': [], 'downloads': []},
                    'brave': {'status': 'invalid_format', 'history': [], 'cookies': [], 'downloads': []},
                    'summary': {
                        'browsers_found': [],
                        'total_history_entries': 0,
                        'total_cookies': 0,
                        'total_downloads': 0,
                        'total_artifacts': 0
                    },
                    'scan_timestamp': datetime.now().isoformat()
                }
            results = _extract_direct_sqlite_db(file_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                report_name = f"browser_artifacts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                report_path = os.path.join(output_dir, report_name)
                with open(report_path, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, default=str)
                results['report_file'] = report_path
            return results

        # Scenario B: Scan system profiles or profile_paths override
        requested_browsers = kwargs.get('browsers', ['chrome', 'edge', 'brave', 'firefox'])
        custom_paths = kwargs.get('profile_paths', {})

        results = {
            'scan_timestamp': datetime.now().isoformat(),
            'system_user': os.path.expanduser('~'),
            'platform': _get_platform(),
            'browsers_requested': requested_browsers,
            'chrome': None,
            'edge': None,
            'brave': None,
            'firefox': None,
            'summary': {},
            'errors': []
        }

        if 'chrome' in requested_browsers:
            path = custom_paths.get('chrome') or _get_chrome_profile_path()
            results['chrome'] = _extract_chromium_artifacts(path, 'Google Chrome')

        if 'edge' in requested_browsers:
            path = custom_paths.get('edge') or _get_edge_profile_path()
            results['edge'] = _extract_chromium_artifacts(path, 'Microsoft Edge')

        if 'brave' in requested_browsers:
            path = custom_paths.get('brave') or _get_brave_profile_path()
            results['brave'] = _extract_chromium_artifacts(path, 'Brave Browser')

        if 'firefox' in requested_browsers:
            path = custom_paths.get('firefox') or _get_firefox_profile_path()
            results['firefox'] = _extract_firefox_artifacts(path)

        browsers_found = []
        total_history = 0
        total_cookies = 0
        total_downloads = 0

        for browser in ['chrome', 'edge', 'brave', 'firefox']:
            data = results.get(browser)
            if data and data.get('status') == 'success':
                browsers_found.append(browser)
                total_history += len(data.get('history', []))
                total_cookies += len(data.get('cookies', []))
                total_downloads += len(data.get('downloads', []))

        results['summary'] = {
            'browsers_found': browsers_found,
            'browsers_not_found': [b for b in requested_browsers if b not in browsers_found],
            'total_history_entries': total_history,
            'total_cookies': total_cookies,
            'total_downloads': total_downloads,
            'total_artifacts': total_history + total_cookies + total_downloads
        }

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            report_name = f"browser_artifacts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            report_path = os.path.join(output_dir, report_name)
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
            results['report_file'] = report_path

        return results