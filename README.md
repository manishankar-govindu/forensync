# ForenSync — Digital Forensics Platform

**ForenSync** is an open-source, modular digital forensics investigation platform developed as a B.Tech Cybersecurity Major Project. It provides case management, cryptographic evidence hashing, signature-based binary file carving, browser artifact parsing, EXIF metadata extraction, and automated forensic report generation in HTML, PDF, and JSON formats.

---

## 📋 Technology Stack

| Layer | Technology |
|---|---|
| **Backend API** | Python 3.9+ / Flask 3.0 |
| **Database** | SQLite via Flask-SQLAlchemy |
| **Authentication** | Session-based with PBKDF2-SHA256 password hashing |
| **Forensic Engine** | Native Python signature-carving & SQLite artifact parsing engines |
| **Report Generation** | Multi-format exports: HTML, PDF (ReportLab), and JSON |

---

## 🔌 Built-In Forensic Modules

ForenSync is designed for cross-platform execution (Windows, Linux, macOS) without requiring external third-party binary tools. All forensic operations run on self-contained, native Python plugin engines:

| Module | Forensic Focus | Implementation & Capabilities |
|---|---|---|
| **File Carver Module** | Header/Footer Carving | Multi-signature scanner (`carver_plugin.py`) supporting JPEG, PNG, PDF, ZIP, GIF, BMP, MP3, EXE |
| **Boundary Extractor** | Strict Boundary Carving | Chunk-based validation requiring mandatory footer matching to reduce false positives |
| **Image Recovery Module** | Multimedia Carving | Target-specific deep carving focused on image structures (JPEG, PNG, BMP) |
| **Browser Artifact Module** | Web Forensics | SQLite parser (`browser_plugin.py`) extracting history, downloads, and cookies |
| **Hash Verifier Module** | Evidence Integrity | Simultaneous MD5, SHA-1, SHA-256, SHA-512 calculation & Shannon entropy analysis |
| **Metadata Extractor Module** | File Header Inspection | EXIF tag parser (`exif_plugin.py`) extracting camera metadata and MIME types |

---

## 🚀 Quick Start & Installation

### Option 1 — Standard Python Setup

1. **Clone the repository and navigate into the folder:**
   ```bash
   cd forensync
   ```

2. **Configure Environment Variables:**
   Copy `.env.example` to `.env` and configure your secret key and credentials:
   ```bash
   cp .env.example .env
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Generate Sample Evidence (Optional):**
   ```bash
   python scripts/generate_sample_evidence.py
   ```

5. **Start the ForenSync Server:**
   ```bash
   python start.py
   ```

6. **Access Dashboard:** Open your browser to `http://localhost:5000`.

---

### Option 2 — Docker Deployment

```bash
docker-compose up --build
```

---

## 🧪 Comprehensive Verification Suite

ForenSync includes automated test suites covering all plugins, security boundaries, and the end-to-end investigation workflow:

```bash
# 1. Plugin Unit Tests (45 Unit Tests)
python tests/test_plugins.py

# 2. End-to-End Investigation Workflow (Login -> Case -> Ingest -> Carve -> Report)
python tests/test_e2e.py

# 3. Live Tool Precision Verification (Disk dump carving accuracy check)
python tests/verify_tools.py
```

---

## 🔐 Security & Chain-of-Custody

- **Integrity Verification:** MD5 and SHA-256 hashes are automatically computed upon evidence upload.
- **Audit Trail:** Investigator actions (logins, uploads, carving, reports) are recorded in the `audit_logs` database table.
- **Access Control:** Role-based access control (Admin, Investigator) with PBKDF2-SHA256 hashed credentials.
- **Web Security:** Hardened headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `X-XSS-Protection`) and restricted CORS origin policies.

---

## 📁 Complete Project Structure

```
forensync/
├── backend/
│   ├── app.py                     # Flask Application & REST API Endpoints
│   ├── models.py                  # Database Models (User, Case, Evidence, AuditLog)
│   ├── core/
│   │   ├── plugin_manager.py      # Dynamic Forensic Plugin Engine
│   │   └── report_generator.py    # HTML & PDF Forensic Report Builder
│   └── templates/
│       ├── index.html             # Investigator Web Dashboard
│       └── login.html             # Login Portal
├── docs/                          # Project Documentation & Architecture Guides
├── frontend/                      # Frontend UI assets and templates
├── plugins/
│   ├── disk/
│   │   ├── carver_plugin.py       # Signature-based File Carver
│   │   ├── imaging_plugin.py      # Disk Imaging Helper
│   │   └── disk_structure_plugin.py # Disk Structure Analyzer
│   ├── metadata/
│   │   ├── hash_plugin.py         # Multi-algorithm Hash & Entropy Plugin
│   │   └── exif_plugin.py         # EXIF Metadata Extractor
│   ├── network/
│   │   ├── browser_plugin.py      # SQLite Browser Artifact Extractor
│   │   └── network_artifact_plugin.py # Network & Communication Parser
│   ├── mobile/
│   │   └── mobile_plugin.py       # Mobile Artifact Extractor
│   ├── memory/
│   │   └── volatility_plugin.py   # Memory Dump Analyzer
│   └── stego/
│       └── stego_plugin.py        # Steganography Detector
├── scripts/
│   ├── generate_sample_evidence.py# Synthetic Forensic Image Generator
│   ├── generate_ctf_challenges.py # CTF Scenario Generator
│   ├── clean_whitespace.py        # Repository Whitespace Normalizer
│   ├── inspect_db.py              # SQLite Record Inspector
│   └── reset_environment.py       # Workspace Reset Helper
├── templates/                     # Base HTML Layout Templates
├── tests/
│   ├── test_plugins.py            # Plugin Unit Test Suite (45 Tests)
│   ├── test_e2e.py                # End-to-End Workflow Test Suite
│   └── verify_tools.py            # Live Precision Verification
├── utils/                         # Forensic Calculation & String Utilities
├── docker-compose.yml             # Container Orchestration
├── Dockerfile                     # Container Build Specification
├── requirements.txt               # Python Dependencies
├── start.py                       # Startup script with auto-dependency installer
├── run.py                         # Alternate entrypoint
├── .env.example                   # Environment configuration template
├── LICENSE.txt                    # Project License
└── README.md                      # Comprehensive Project Documentation
```

---

## 👥 Project Team & Credits

**Tool: ForenSync — File Carving in Digital Forensics**
**B.Tech Cybersecurity Major Project (2025–2026)**
**Parul Institute of Engineering and Technology, Parul University**

### Team Members:
* **GOVINDU MANISHANKAR** (Enrolment No: `2303031260070`) — *Team Leader*
* **DOSAKAYALA RAMA SUBBA REDDY** (Enrolment No: `2303031260057`)
* **JINGU MURALI MOHAN REDDY** (Enrolment No: `2303031260089`)
* **KAILA JOHN WESLEY** (Enrolment No: `2303031260097`)

### Faculty Guides:
* **Mr. Pirmohammad Khan / Mr. Shivam Chandra** (Department of CSE Cybersecurity)
* **Dr. Mukesh Patidar** (Associate Professor, Department of CSE Cybersecurity)
