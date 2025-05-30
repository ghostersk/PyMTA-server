"""
Modular SMTP Server with DKIM support.
Main server file that ties all modules together.
"""

import asyncio
import logging
import sys
import os

# Import our modules
from .config import SMTP_PORT, SMTP_TLS_PORT, HOSTNAME, LOG_LEVEL
from .models import create_tables
from .smtp_handler import CustomSMTPHandler, PlainController
from .tls_utils import generate_self_signed_cert, create_ssl_context
from .dkim_manager import DKIMManager
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP as AIOSMTP

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Enable asyncio debugging
try:
    loop = asyncio.get_running_loop()
    loop.set_debug(True)
except RuntimeError:
    # No running loop, set debug when we create one
    pass

async def start_server():
    """Main server function."""
    logger.info("Starting SMTP Server with DKIM support...")
    
    # Initialize database
    logger.info("Initializing database...")
    create_tables()
    
    # Initialize DKIM manager and generate keys for domains without them
    logger.info("Initializing DKIM manager...")
    dkim_manager = DKIMManager()
    dkim_manager.initialize_default_keys()
    
    # Add test data if needed
    from .models import Session, Domain, User, WhitelistedIP, hash_password
    session = Session()
    try:
        # Add example.com domain if not exists
        domain = session.query(Domain).filter_by(domain_name='example.com').first()
        if not domain:
            domain = Domain(domain_name='example.com', requires_auth=True)
            session.add(domain)
            session.commit()
            logger.info("Added example.com domain")
        
        # Add test user if not exists
        user = session.query(User).filter_by(email='test@example.com').first()
        if not user:
            user = User(
                email='test@example.com',
                password_hash=hash_password('testpass123'),
                domain_id=domain.id
            )
            session.add(user)
            session.commit()
            logger.info("Added test user: test@example.com")
        
        # Add whitelisted IP if not exists
        whitelist = session.query(WhitelistedIP).filter_by(ip_address='127.0.0.1').first()
        if not whitelist:
            whitelist = WhitelistedIP(ip_address='127.0.0.1', domain_id=domain.id)
            session.add(whitelist)
            session.commit()
            logger.info("Added whitelisted IP: 127.0.0.1")
    except Exception as e:
        session.rollback()
        logger.error(f"Error adding test data: {e}")
    finally:
        session.close()
    
    # Generate SSL certificate if it doesn't exist
    logger.info("Checking SSL certificates...")
    if not generate_self_signed_cert():
        logger.error("Failed to generate SSL certificate")
        return
    
    # Create SSL context
    ssl_context = create_ssl_context()
    if not ssl_context:
        logger.error("Failed to create SSL context")
        return
    
    # Start plain SMTP server (with IP whitelist fallback)
    handler_plain = CustomSMTPHandler()
    controller_plain = PlainController(
        handler_plain,
        hostname=HOSTNAME,
        port=SMTP_PORT
    )
    controller_plain.start()
    logger.info(f'Starting plain SMTP server on {HOSTNAME}:{SMTP_PORT}...')
    
    # Start TLS SMTP server using closure pattern like the original
    handler_tls = CustomSMTPHandler()
    
    # Define TLS controller class with ssl_context in closure (like original)
    class TLSController(Controller):
        def factory(self):
            return AIOSMTP(
                self.handler,
                tls_context=ssl_context,  # Use ssl_context from closure
                require_starttls=False,  # Don't force STARTTLS, but make it available
                auth_require_tls=True,   # If auth is used, require TLS
                authenticator=self.handler.combined_authenticator,
                decode_data=True,
                hostname=self.hostname
            )
    
    controller_tls = TLSController(
        handler_tls,
        hostname=HOSTNAME,
        port=SMTP_TLS_PORT
    )
    controller_tls.start()
    logger.info(f'Starting STARTTLS SMTP server on {HOSTNAME}:{SMTP_TLS_PORT}...')
    
    logger.info('Both SMTP servers are running:')
    logger.info(f'  - Plain SMTP (IP whitelist): {HOSTNAME}:{SMTP_PORT}')
    logger.info(f'  - STARTTLS SMTP (auth required): {HOSTNAME}:{SMTP_TLS_PORT}')
    logger.info('  - DKIM signing enabled for configured domains')
    logger.info('')
    logger.info('Management commands:')
    logger.info('  python cli_tools.py --help')
    logger.info('')
    logger.info('Press Ctrl+C to stop the servers...')
    
    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        logger.info('Shutting down SMTP servers...')
        controller_plain.stop()
        controller_tls.stop()
        logger.info('SMTP servers stopped.')

if __name__ == '__main__':
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        logger.info('Server interrupted by user')
        sys.exit(0)
    except Exception as e:
        logger.error(f'Server error: {e}')
        sys.exit(1)
