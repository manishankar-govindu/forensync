# ForenSync — Digital Forensics Platform

**ForenSync** is a B.Tech final-year project implementing a web-based digital forensics analysis platform. It provides case management, evidence upload with integrity hashing, file carving, browser artifact extraction, metadata analysis, and forensic report generation.

---

## 📋 Project Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.9 + Flask 3.0 |
| Database | SQLite via Flask-SQLAlchemy |
| Auth | Session-based (Flask sessions + Werkzeug password hashing) |
| Plugin System | Python importlib auto-discovery |
| Reports | HTML + PDF (reportlab) + JSON |

---

### Option 1 — Run with Docker (Recommended)

```bash
docker-compose up --build
```

### Option 2 — Run with Python

Open a terminal in the project root folder and run:

```bash
pip install -r requirements.txt
```

> **Note:** `python-magic` may require an extra step on Windows.
> If it causes an error, remove it from `requirements.txt` — it is optional.

### Step 2 — Start the Server

```bash
cd backend
python app.py
```

Or from the project root:

```bash
python start.py
```

### Step 3 — Open in Browser

```
http://localhost:5000
```

### Default Login Credentials

| Username | Password | Role |
|---|---|---|
| `admin`        | `admin123`  | Administrator |
| `investigator` | `invest123` | Investigator  |

> ⚠️ **Warning:** Change default passwords before any non-local deployment.

---

## 📁 Project Structure

```
forensync/
├── backend/
│   ├── app.py
│   ├── models.py
│   ├── core/
│   │   ├── plugin_manager.py
│   │   └── report_generator.py
│   └── templates/
│       ├── index.html
│       └── login.html
├── plugins/
│   ├── metadata/
│   │   ├── exif_plugin.py
│   │   └── hash_plugin.py
│   ├── disk/
│   │   └── carver_plugin.py
│   └── network/
│       └── browser_plugin.py
├── scripts/
├── templates/
├── tests/
│   └── test_plugins.py
├── instance/
├── evidence/
├── reports/
├── .gitignore
├── .dockerignore
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── run.py
├── start.py
└── LICENSE.txt
```

---

## 🔌 Available Plugins

| Plugin | Name in UI | What It Does |
|---|---|---|
| `exif_plugin.py` | Metadata Extractor | Extracts EXIF data, GPS coordinates, camera info from images |
| `hash_plugin.py` | Hash Verifier | Computes MD5, SHA1, SHA256, SHA512 + Shannon entropy |
| `carver_plugin.py` | File Carver | Recovers JPEG, PNG, PDF, ZIP, GIF, BMP, MP3, EXE from raw bytes |
| `browser_plugin.py` | Browser Artifact Extractor | Extracts Chrome/Edge/Brave/Firefox history, downloads, cookies |

---

## 🌐 API Endpoints

### Authentication
| Method | Endpoint | Description |
|---|---|---|
| GET/POST | `/login` | Web login page |
| POST | `/api/auth/login` | REST login |
| POST | `/api/auth/logout` | REST logout |
| GET | `/api/auth/me` | Current session info |

### Cases
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/cases` | List all cases |
| POST | `/api/cases` | Create new case |

### Evidence
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/upload` | Upload evidence file |
| GET | `/api/evidence` | List evidence (filter by `?case_id=`) |

### Analysis
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/plugins` | List available plugins |
| POST | `/api/analyze` | Run a plugin on an evidence file |

### Reports
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/cases/<id>/report` | Generate HTML report |
| GET | `/api/cases/<id>/report/pdf` | Generate PDF report |
| GET | `/api/cases/<id>/report/json` | Export JSON data dump |

### Admin
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/audit-log` | View audit trail (admin only) |
| GET | `/api/status` | Server health check |

---

## 🧪 Running Tests

From the project root directory:

```bash
python tests/test_plugins.py
```

Or with pytest (if installed):

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## 📑 Generating a Report

After creating a case and uploading evidence:

```bash
# HTML Report (open in browser)
GET http://localhost:5000/api/cases/<case_id>/report

# PDF Report
GET http://localhost:5000/api/cases/<case_id>/report/pdf

# JSON Export
GET http://localhost:5000/api/cases/<case_id>/report/json
```

---

## 🔐 Security Notes

- Passwords are hashed using **PBKDF2-SHA256** (via Werkzeug)
- All routes (except login and status) require an authenticated session
- The `AuditLog` table records every login, logout, case creation, upload, and analysis
- Evidence files are stored with a timestamp prefix to avoid filename collisions
- MD5 hash is computed on upload for chain-of-custody integrity

---

## 📌 Writing Your Own Plugin

1. Create a new `.py` file inside any `plugins/` subdirectory — name it `<something>_plugin.py`
2. Inherit from `ForensicPlugin`:

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from backend.core.plugin_manager import ForensicPlugin

class MyPlugin(ForensicPlugin):

    @property
    def name(self): return "My Plugin"

    @property
    def description(self): return "What it does"

    @property
    def version(self): return "1.0.0"

    def supported_types(self): return ['.txt', '.log']

    def analyze(self, file_path, output_dir=None, **kwargs):
        # Your analysis logic here
        return {'result': 'data'}
```

3. Restart the server — the plugin is auto-discovered.

---
## Known Limitations

1. **Async Carving Tasks**: Background file carving uses in-memory task storage. 
   Tasks persist only while the Flask server is running. 
   **Mitigation**: Use Redis for production deployment (documented in future work).

2. **Mobile Plugin**: Requires actual SQLite database files (contacts.db, messages.db, etc). 
   Defaults to mock data if tables missing.

3. **Tool Execution**: Tools run via local subprocess for training scenarios. 
   Production deployment would use container orchestration (Kubernetes).

---

## 👥 Project Team & Credits
**Tool: ForenSync — File Carving in Digital Forensics**  

**B.Tech Cybersecurity Major Project (2025–2026)**  
**Parul Institute of Engineering and Technology, Parul University**  

### Team Leader:
* **GOVINDU MANISHANKAR** (Enrolment No: `2303031260070`)

### Team Members:
* **DOSAKAYALA RAMA SUBBA REDDY** (Enrolment No: `2303031260057`)
* **JINGU MURALI MOHAN REDDY** (Enrolment No: `2303031260089`)
* **KAILA JOHN WESLEY** (Enrolment No: `2303031260097`)

### Assistant Professor / Project Guide:
* **Mr. Pirmohammad Khan / Mr. Shivam Chandra** (Department of CSE Cybersecurity)

### Associate Professor:
* **Dr. Mukesh Patidar** (Department of CSE Cybersecurity)
