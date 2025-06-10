"""
Modular SMTP Server with DKIM support.
Main server file that ties all modules together.
"""

import asyncio
from email_server.settings_loader import load_settings
from email_server.tool_box import get_logger

# Import our modules
from email_server.models import create_tables
from email_server.smtp_handler import EnhancedCustomSMTPHandler, PlainController, TLSController
from email_server.tls_utils import generate_self_signed_cert, create_ssl_context
from email_server.dkim_manager import DKIMManager
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP as AIOSMTP

settings = load_settings()
SMTP_PORT = int(settings['Server']['SMTP_PORT'])
SMTP_TLS_PORT = int(settings['Server']['SMTP_TLS_PORT'])
HOSTNAME = settings['Server'].get('helo_hostname', settings['Server'].get('hostname', 'localhost'))
LOG_LEVEL = settings['Logging']['LOG_LEVEL']
BIND_IP = settings['Server']['BIND_IP']

logger = get_logger()

# Enable asyncio debugging
try:
    loop = asyncio.get_running_loop()
    loop.set_debug(True)
except RuntimeError:
    # No running loop, set debug when we create one
    pass

async def start_server(shutdown_event=None):
    """Main server function."""
    logger.debug("Starting SMTP Server with DKIM support...")
    
    # Initialize database
    logger.debug("Initializing database...")
    create_tables()
    
    # Initialize DKIM manager (do not auto-generate keys for all domains)
    logger.debug("Initializing DKIM manager...")
    dkim_manager = DKIMManager()
    # dkim_manager.initialize_default_keys()  # Removed: do not auto-generate DKIM keys for all domains
    
    # Add test data if needed
    from .models import Session, Domain, Sender, WhitelistedIP, hash_password
    session = Session()
    try:
        # Add example.com domain if not exists
        domain = session.query(Domain).filter_by(domain_name='example.com').first()
        if not domain:
            domain = Domain(domain_name='example.com')
            session.add(domain)
            session.commit()
            logger.debug("Added example.com domain")
        
        # Add test sender if not exists
        sender = session.query(Sender).filter_by(email='test@example.com').first()
        if not sender:
            sender = Sender(
                email='test@example.com',
                password_hash=hash_password('testpass123'),
                domain_id=domain.id
            )
            session.add(sender)
            session.commit()
            logger.debug("Added test sender: test@example.com")
        
        # Add whitelisted IP if not exists
        whitelist = session.query(WhitelistedIP).filter_by(ip_address='127.0.0.1').first()
        if not whitelist:
            whitelist = WhitelistedIP(ip_address='127.0.0.1', domain_id=domain.id)
            session.add(whitelist)
            session.commit()
            logger.debug("Added whitelisted IP: 127.0.0.1")
    except Exception as e:
        session.rollback()
        logger.error(f"Error adding test data: {e}")
    finally:
        session.close()
    
    # Generate SSL certificate if it doesn't exist
    logger.debug("Checking SSL certificates...")
    if not generate_self_signed_cert():
        logger.error("Failed to generate SSL certificate")
        return
    
    # Create SSL context
    ssl_context = create_ssl_context()
    if not ssl_context:
        logger.error("Failed to create SSL context")
        return
    
    logger.debug(f"SSL context created: {ssl_context}")
    logger.debug(f"SSL context type: {type(ssl_context)}")
    
    # Start plain SMTP server (with IP whitelist fallback)
    handler_plain = EnhancedCustomSMTPHandler()
    controller_plain = PlainController(
        handler_plain,
        hostname=HOSTNAME,  # Use proper hostname for HELO identification
        port=SMTP_PORT
    )
    controller_plain.start()
    logger.debug(f'Starting plain SMTP server on {HOSTNAME}:{SMTP_PORT}...')
    
    # Start TLS SMTP server using the updated TLSController
    handler_tls = EnhancedCustomSMTPHandler()
    controller_tls = TLSController(
        handler_tls,
        ssl_context=ssl_context,
        hostname=HOSTNAME,  # Use proper hostname for HELO identification  
        port=SMTP_TLS_PORT
    )
    controller_tls.start()
    logger.debug(f'  - Plain SMTP (IP whitelist): {BIND_IP}:{SMTP_PORT}')
    logger.debug(f'  - STARTTLS SMTP (auth required): {BIND_IP}:{SMTP_TLS_PORT}')
    logger.debug('Management available via web interface at: http://localhost:5000/email')
    
    try:
        if shutdown_event is not None:
            await shutdown_event.wait()
        else:
            await asyncio.Event().wait()
    except KeyboardInterrupt:
        logger.debug('Shutting down SMTP servers...')
    finally:
        controller_plain.stop()
        controller_tls.stop()
        logger.debug('SMTP servers stopped.')