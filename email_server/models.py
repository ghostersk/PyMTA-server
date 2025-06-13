"""
Database models for the SMTP server using ESRV schema.

Enhanced security features:
- Users can only send as their own email or domain emails (if permitted)
- IP authentication is domain-specific
- All tables use 'esrv_' prefix for namespace isolation
"""

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy.sql import func
from datetime import datetime
import bcrypt
from email_server.settings_loader import load_settings
from email_server.tool_box import ensure_folder_exists, get_logger

settings = load_settings()
# ConfigParser keys are case-insensitive, so we can use either case
DATABASE_URL = settings['Database']['database_url']

ensure_folder_exists(DATABASE_URL)

# SQLAlchemy setup
Base = declarative_base()
engine = create_engine(DATABASE_URL, echo=False)
Session = sessionmaker(bind=engine)

logger = get_logger()

class Domain(Base):
    """Domain model with enhanced security features."""
    __tablename__ = 'esrv_domains'
    
    id = Column(Integer, primary_key=True)
    domain_name = Column(String, unique=True, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    
    # Add relationships with proper foreign key references
    senders = relationship("Sender", backref="domain", lazy="joined")
    dkim_keys = relationship("DKIMKey", backref="domain", lazy="joined")
    whitelisted_ips = relationship("WhitelistedIP", backref="domain", lazy="joined")
    custom_headers = relationship("CustomHeader", backref="domain", lazy="joined")
    
    def __repr__(self):
        return f"<Domain(id={self.id}, domain_name='{self.domain_name}', active={self.is_active})>"

class Sender(Base):
    """
    Sender model with enhanced authentication controls.
    
    Security features:
    - can_send_as_domain: If True, sender can send as any email from their domain
    - If False, sender can only send as their own email address
    """
    __tablename__ = 'esrv_senders'
    
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    domain_id = Column(Integer, ForeignKey('esrv_domains.id'), nullable=False)
    can_send_as_domain = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    store_message_content = Column(Boolean, default=False)  # Store message body/attachments
    
    def can_send_as(self, from_address: str) -> bool:
        """
        Check if this sender can send emails as the given from_address.
        
        Args:
            from_address: The email address the sender wants to send from
        Returns:
            True if sender is allowed to send as this address
        """
        # Sender can always send as their own email
        if from_address.lower() == self.email.lower():
            return True
        # If sender has domain privileges, check if from_address is from same domain
        if self.can_send_as_domain:
            sender_domain = self.email.split('@')[1].lower()
            from_domain = from_address.split('@')[1].lower() if '@' in from_address else ''
            return sender_domain == from_domain
        return False
    
    def __repr__(self):
        return f"<Sender(id={self.id}, email='{self.email}', domain_id={self.domain_id}, can_send_as_domain={self.can_send_as_domain})>"

class WhitelistedIP(Base):
    """
    IP whitelist model with domain-specific authentication.
    
    Security feature:
    - IPs can only send emails for their specific authorized domain
    """
    __tablename__ = 'esrv_whitelisted_ips'
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String, nullable=False)
    domain_id = Column(Integer, ForeignKey('esrv_domains.id'), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    store_message_content = Column(Boolean, default=False)  # Store message body/attachments
    
    def can_send_for_domain(self, domain_name: str) -> bool:
        """
        Check if this IP can send emails for the given domain.
        
        Args:
            domain_name: The domain name to check
            
        Returns:
            True if IP is authorized for this domain
        """
        if not self.is_active:
            return False
            
        # Need to check against the actual domain
        session = Session()
        try:
            domain = session.query(Domain).filter_by(
                domain_name=domain_name.lower(),
                is_active=True
            ).first()
            return domain and domain.id == self.domain_id
        finally:
            session.close()
    
    def __repr__(self):
        return f"<WhitelistedIP(id={self.id}, ip='{self.ip_address}', domain_id={self.domain_id})>"

class EmailLog(Base):
    """Email log model for tracking sent emails."""
    __tablename__ = 'esrv_email_logs'
    
    id = Column(Integer, primary_key=True)
    message_id = Column(String, unique=True, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    peer_ip = Column(String, nullable=False)  # Store only IP address
    mail_from = Column(String, nullable=False)
    to_address = Column(String, nullable=False, server_default='')
    cc_addresses = Column(String, nullable=True, server_default='')  # Comma-separated CC
    bcc_addresses = Column(String, nullable=True, server_default='')  # Comma-separated BCC
    subject = Column(Text, nullable=True)
    email_headers = Column(Text, nullable=False)  # Store only email headers
    message_body = Column(Text, nullable=True)  # Store actual message content
    status = Column(String, nullable=False)
    dkim_signed = Column(Boolean, default=False)
    username = Column(String, nullable=True)  # Authenticated username
    created_at = Column(DateTime, default=func.now())

    recipients = relationship("EmailRecipientLog", back_populates="email_log", cascade="all, delete-orphan")
    attachments = relationship("EmailAttachment", back_populates="email_log", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<EmailLog(id={self.id}, message_id='{self.message_id}', from='{self.mail_from}', to='{self.to_address}', status='{self.status}')>"

class EmailRecipientLog(Base):
    """Log for each recipient of an email, including status and error details."""
    __tablename__ = 'esrv_email_recipient_logs'

    id = Column(Integer, primary_key=True)
    email_log_id = Column(Integer, ForeignKey('esrv_email_logs.id'), nullable=False)
    recipient = Column(String, nullable=False)
    recipient_type = Column(String, nullable=False)  # 'to', 'cc', 'bcc'
    status = Column(String, nullable=False)  # 'success', 'failed', etc.
    error_code = Column(String, nullable=True)
    error_message = Column(Text, nullable=True)
    server_response = Column(Text, nullable=True)

    email_log = relationship("EmailLog", back_populates="recipients")

    def __repr__(self):
        return f"<EmailRecipientLog(id={self.id}, recipient='{self.recipient}', type='{self.recipient_type}', status='{self.status}')>"

class AuthLog(Base):
    """Authentication log model for security auditing."""
    __tablename__ = 'esrv_auth_logs'
    
    id = Column(Integer, primary_key=True)
    auth_type = Column(String, nullable=False)  # 'user' or 'ip'
    identifier = Column(String, nullable=False)  # email or IP address
    ip_address = Column(String)
    success = Column(Boolean, nullable=False)
    message = Column(Text)
    created_at = Column(DateTime, default=func.now())
    
    def __repr__(self):
        return f"<AuthLog(id={self.id}, type='{self.auth_type}', identifier='{self.identifier}', success={self.success})>"

class DKIMKey(Base):
    """DKIM key model for email signing."""
    __tablename__ = 'esrv_dkim_keys'
    
    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey('esrv_domains.id'), nullable=False)
    selector = Column(String, nullable=False, default='default')
    private_key = Column(Text, nullable=False)
    public_key = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    replaced_at = Column(DateTime, nullable=True)  # When this key was replaced by a new one
    
    def __repr__(self):
        return f"<DKIMKey(id={self.id}, domain_id={self.domain_id}, selector='{self.selector}', active={self.is_active})>"

class CustomHeader(Base):
    """Custom header model for domain-specific email headers."""
    __tablename__ = 'esrv_custom_headers'
    
    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey('esrv_domains.id'), nullable=False)
    header_name = Column(String, nullable=False)
    header_value = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    
    def __repr__(self):
        return f"<CustomHeader(id={self.id}, domain_id={self.domain_id}, header='{self.header_name}: {self.header_value}', active={self.is_active})>"

class EmailAttachment(Base):
    """Attachment metadata and file path, linked to EmailLog."""
    __tablename__ = 'esrv_email_attachments'

    id = Column(Integer, primary_key=True)
    email_log_id = Column(Integer, ForeignKey('esrv_email_logs.id'), nullable=False)
    filename = Column(String, nullable=False)
    content_type = Column(String, nullable=True)
    file_path = Column(String, nullable=False)  # Path on disk
    size = Column(Integer, nullable=True)
    uploaded_at = Column(DateTime, default=func.now())

    email_log = relationship("EmailLog", back_populates="attachments")

    def __repr__(self):
        return f"<EmailAttachment(id={self.id}, filename='{self.filename}', file_path='{self.file_path}')>"


def create_tables():
    """Create all database tables using ESRV schema."""
    Base.metadata.create_all(engine)
    logger.info("Created ESRV database tables")

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password: str, hashed: str) -> bool:
    """Check a password against its hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def log_auth_attempt(auth_type: str, identifier: str, ip_address: str, 
                     success: bool, message: str) -> None:
    """
    Log an authentication attempt for security auditing.
    
    Args:
        auth_type: Type of auth ('user' or 'ip')
        identifier: User email or IP address
        ip_address: Client IP address
        success: Whether auth was successful
        message: Additional details
    """
    session = Session()
    try:
        auth_log = AuthLog(
            auth_type=auth_type,
            identifier=identifier,
            ip_address=ip_address,
            success=success,
            message=message
        )
        session.add(auth_log)
        session.commit()
        logger.info(f"Auth log: {auth_type} {identifier} from {ip_address} - {'SUCCESS' if success else 'FAILED'}")
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to log auth attempt: {e}")
    finally:
        session.close()

def log_email(from_address: str, to_address: str, subject: str, 
              status: str, message: str = None) -> None:
    """
    Log an email send attempt.
    
    Args:
        from_address: Sender email
        to_address: Recipient email  
        subject: Email subject
        status: Send status ('sent', 'failed', etc.)
        message: Additional details
    """
    session = Session()
    try:
        email_log = EmailLog(
            from_address=from_address,
            to_address=to_address,
            subject=subject,
            status=status,
            message=message
        )
        session.add(email_log)
        session.commit()
        logger.info(f"Email log: {from_address} -> {to_address} - {status}")
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to log email: {e}")
    finally:
        session.close()

def get_sender_by_email(email: str):
    """Get sender by email address."""
    session = Session()
    try:
        return session.query(Sender).filter_by(email=email.lower(), is_active=True).first()
    finally:
        session.close()

def get_domain_by_name(domain_name: str):
    """Get domain by name."""
    session = Session()
    try:
        return session.query(Domain).filter_by(domain_name=domain_name.lower(), is_active=True).first()
    finally:
        session.close()

def get_whitelisted_ip(ip_address: str, domain_name: str = None):
    """
    Get whitelisted IP, optionally filtered by domain.
    
    Args:
        ip_address: IP address to check
        domain_name: Optional domain name to restrict to
        
    Returns:
        WhitelistedIP object if found and authorized for domain
    """
    session = Session()
    try:
        query = session.query(WhitelistedIP).filter_by(
            ip_address=ip_address,
            is_active=True
        )
        
        if domain_name:
            # Join with domain to check authorization
            domain = session.query(Domain).filter_by(
                domain_name=domain_name.lower(),
                is_active=True
            ).first()
            if not domain:
                return None
            query = query.filter_by(domain_id=domain.id)
            
        return query.first()
    finally:
        session.close()
