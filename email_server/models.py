"""
Database models for the SMTP server.
"""

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import bcrypt
from email_server.settings_loader import load_settings
from email_server.tool_box import ensure_folder_exists, get_logger

settings = load_settings()
DATABASE_URL = settings['Database']['DATABASE_URL']

ensure_folder_exists(DATABASE_URL)

# SQLAlchemy setup
Base = declarative_base()
engine = create_engine(DATABASE_URL, echo=False)
Session = sessionmaker(bind=engine)

logger = get_logger()

class Domain(Base):
    __tablename__ = 'domains'
    id = Column(Integer, primary_key=True)
    domain_name = Column(String, unique=True, nullable=False)
    requires_auth = Column(Boolean, default=True)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    domain_id = Column(Integer, nullable=False)

class WhitelistedIP(Base):
    __tablename__ = 'whitelisted_ips'
    id = Column(Integer, primary_key=True)
    ip_address = Column(String, unique=True, nullable=False)
    domain_id = Column(Integer, nullable=False)

class EmailLog(Base):
    __tablename__ = 'email_logs'
    id = Column(Integer, primary_key=True)
    message_id = Column(String, unique=True, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    peer = Column(String, nullable=False)
    mail_from = Column(String, nullable=False)
    rcpt_tos = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    status = Column(String, nullable=False)
    dkim_signed = Column(Boolean, default=False)

class AuthLog(Base):
    __tablename__ = 'auth_logs'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False)
    peer = Column(String, nullable=False)
    username = Column(String)
    success = Column(Boolean, nullable=False)
    message = Column(String, nullable=False)

class DKIMKey(Base):
    __tablename__ = 'dkim_keys'
    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, nullable=False)
    selector = Column(String, nullable=False)
    private_key = Column(Text, nullable=False)
    public_key = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.now)
    is_active = Column(Boolean, default=True)

def create_tables():
    """Create all database tables."""
    Base.metadata.create_all(engine)

def hash_password(password):
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed):
    """Check a password against its hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
