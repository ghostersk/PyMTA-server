"""
TLS utilities for the SMTP server.
"""

import ssl
import os
from OpenSSL import crypto
from email_server.settings_loader import load_settings
from email_server.tool_box import ensure_folder_exists, get_logger

settings = load_settings()
TLS_CERT_FILE = settings['TLS']['TLS_CERT_FILE']
TLS_KEY_FILE = settings['TLS']['TLS_KEY_FILE']

logger = get_logger()

ensure_folder_exists(TLS_CERT_FILE)
ensure_folder_exists(TLS_KEY_FILE)

def generate_self_signed_cert():
    """Generate self-signed SSL certificate if it doesn't exist."""
    if os.path.exists(TLS_CERT_FILE) and os.path.exists(TLS_KEY_FILE):
        logger.debug("SSL certificate already exists")
        return True
    
    try:
        logger.debug("Generating self-signed SSL certificate...")
        
        # Generate private key
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        
        # Generate certificate
        cert = crypto.X509()
        cert.get_subject().CN = 'localhost'
        cert.get_subject().O = 'PyMTA Server'
        cert.get_subject().C = 'GB'
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # Valid for 1 year
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')
        
        # Write certificate
        with open(TLS_CERT_FILE, 'wb') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        
        # Write private key
        with open(TLS_KEY_FILE, 'wb') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        
        logger.debug(f"SSL certificate generated: {TLS_CERT_FILE}, {TLS_KEY_FILE}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to generate SSL certificate: {e}")
        return False

def create_ssl_context():
    """Create SSL context for TLS support."""
    try:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=TLS_CERT_FILE, keyfile=TLS_KEY_FILE)
        ssl_context.set_ciphers('DEFAULT')  # Relax ciphers for compatibility
        logger.debug('SSL context created successfully')
        return ssl_context
    except Exception as e:
        logger.error(f'Failed to create SSL context: {e}')
        return None
