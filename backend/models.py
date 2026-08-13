# models.py - Database models for ForenSync

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid

db = SQLAlchemy()

class User(db.Model):
    """User accounts for investigators"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default='investigator')  # admin, investigator, viewer
    department = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    cases = db.relationship('Case', backref='investigator', lazy=True)
    
    def set_password(self, password):
        """Hash and store password"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        """Verify password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role == 'admin'
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'role': self.role,
            'department': self.department,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class Case(db.Model):
    """Forensic investigation cases"""
    __tablename__ = 'cases'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_number = db.Column(db.String(50), unique=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    case_type = db.Column(db.String(50))  # criminal, civil, internal, incident_response
    status = db.Column(db.String(20), default='active')  # active, closed, archived
    priority = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    
    # Foreign keys
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at = db.Column(db.DateTime)
    
    # Relationships
    evidence_items = db.relationship('Evidence', backref='case', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'case_number': self.case_number,
            'title': self.title,
            'description': self.description,
            'case_type': self.case_type,
            'status': self.status,
            'priority': self.priority,
            'created_by': self.created_by,
            'investigator_name': self.investigator.full_name if self.investigator else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'evidence_count': len(self.evidence_items)
        }

class Evidence(db.Model):
    """Evidence files uploaded to cases"""
    __tablename__ = 'evidence'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = db.Column(db.String(36), db.ForeignKey('cases.id'), nullable=True)
    
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.BigInteger)
    file_type = db.Column(db.String(100))
    mime_type = db.Column(db.String(100))
    
    # Hashes for integrity
    md5_hash = db.Column(db.String(32))
    sha1_hash = db.Column(db.String(40))
    sha256_hash = db.Column(db.String(64))
    
    # Metadata
    description = db.Column(db.Text)
    tags = db.Column(db.String(500))  # comma-separated tags
    source = db.Column(db.String(200))  # where evidence came from
    seized_by = db.Column(db.String(100))
    seized_date = db.Column(db.DateTime)
    
    # Analysis status
    analysis_status = db.Column(db.String(20), default='pending')  # pending, processing, completed, failed
    analysis_results = db.Column(db.Text)  # JSON string of results
    
    # Chain of custody
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    uploader = db.relationship('User', foreign_keys=[uploaded_by], backref='uploads')

    def to_dict(self):
        return {
            'id': self.id,
            'case_id': self.case_id,
            'filename': self.filename,
            'original_filename': self.original_filename,
            'file_size': self.file_size,
            'file_size_human': self._format_bytes(self.file_size) if self.file_size else 'Unknown',
            'file_type': self.file_type,
            'mime_type': self.mime_type,
            'md5_hash': self.md5_hash,
            'sha256_hash': self.sha256_hash,
            'description': self.description,
            'tags': self.tags,
            'analysis_status': self.analysis_status,
            'analysis_results': self.analysis_results,
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else None,
            'uploader_name': self.uploader.full_name if self.uploader else None
        }
    
    def _format_bytes(self, size):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"

class AuditLog(db.Model):
    """Track all actions for forensic integrity"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # login, logout, create_case, upload_evidence, run_analysis, etc.
    resource_type = db.Column(db.String(50))  # case, evidence, user, system
    resource_id = db.Column(db.String(36))
    details = db.Column(db.Text)  # JSON string with additional details
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'user_id': self.user_id,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': self.details
        }

class CTFScore(db.Model):
    """CTF challenge completion scores and timestamps"""
    __tablename__ = 'ctf_scores'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    scenario_id = db.Column(db.String(50), nullable=False)
    score = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.username,
            'scenario_id': self.scenario_id,
            'score': self.score,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

# Initialize database with default admin user
def init_db(app):
    """Initialize database and create default admin"""
    with app.app_context():
        db.create_all()
        
        # Create admin user if doesn't exist
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@forensync.local',
                full_name='System Administrator',
                role='admin',
                department='IT Security'
            )
            admin.set_password('admin123')  # Change this in production!
            db.session.add(admin)
            
            # Create demo investigator
            investigator = User(
                username='investigator',
                email='inv@forensync.local',
                full_name='Demo Investigator',
                role='investigator',
                department='Cyber Crime Unit'
            )
            investigator.set_password('invest123')
            db.session.add(investigator)
            
            db.session.commit()
            print("[OK] Default users created:")
            print("   Admin: admin / admin123")
            print("   Investigator: investigator / invest123")