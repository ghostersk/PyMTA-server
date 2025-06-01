"""
DKIM key management and email signing functionality.
"""

import dkim
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime
from email_server.models import Session, Domain, DKIMKey, CustomHeader
from email_server.settings_loader import load_settings
from email_server.tool_box import get_logger
import random
import string

settings = load_settings()
DKIM_KEY_SIZE = int(settings['DKIM']['DKIM_KEY_SIZE'])

logger = get_logger()

class DKIMManager:
    """Manages DKIM keys and email signing."""
    
    def __init__(self, selector: str = None):
        """Initialize DKIMManager with a selector. If not provided, use random."""
        if selector:
            self.selector = selector
        else:
            self.selector = self._generate_random_selector()
    
    @staticmethod
    def _generate_random_selector(length: int = 12) -> str:
        """Generate a random DKIM selector name (8-12 chars)."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    def generate_dkim_keypair(self, domain_name, selector: str = None):
        """Generate DKIM key pair for a domain, optionally with a custom selector."""
        session = Session()
        try:
            # Check if domain exists
            domain = session.query(Domain).filter_by(domain_name=domain_name).first()
            if not domain:
                logger.error(f"Domain {domain_name} not found")
                return False
            
            # Use provided selector or instance selector
            use_selector = selector or self.selector
            
            # Check if DKIM key with this selector already exists
            existing_key = session.query(DKIMKey).filter_by(domain_id=domain.id, selector=use_selector, is_active=True).first()
            if existing_key:
                logger.debug(f"DKIM key already exists for domain {domain_name} and selector {use_selector}")
                return True
            
            # Generate RSA key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=DKIM_KEY_SIZE
            )
            
            # Get private key in PEM format
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            # Get public key in PEM format
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            # Store in database
            dkim_key = DKIMKey(
                domain_id=domain.id,
                selector=use_selector,
                private_key=private_pem,
                public_key=public_pem,
                created_at=datetime.now(),
                is_active=True
            )
            session.add(dkim_key)
            session.commit()
            
            logger.debug(f"Generated DKIM key for domain: {domain_name} selector: {use_selector}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Error generating DKIM key for {domain_name}: {e}")
            return False
        finally:
            session.close()

    def get_active_dkim_key(self, domain_name):
        """Get the active DKIM key for a domain (only one active per selector)."""
        session = Session()
        try:
            domain = session.query(Domain).filter_by(domain_name=domain_name).first()
            if not domain:
                return None
            dkim_key = session.query(DKIMKey).filter_by(domain_id=domain.id, is_active=True).first()
            return dkim_key
        except Exception as e:
            logger.error(f"Error getting DKIM key for {domain_name}: {e}")
            return None
        finally:
            session.close()

    def get_dkim_private_key(self, domain_name):
        """Get DKIM private key for a domain."""
        dkim_key = self.get_active_dkim_key(domain_name)
        if dkim_key:
            return dkim_key.private_key
        return None
    
    def get_dkim_public_key_record(self, domain_name):
        """Get DKIM public key DNS record for a domain (active key only)."""
        dkim_key = self.get_active_dkim_key(domain_name)
        if dkim_key:
            public_key_lines = dkim_key.public_key.strip().split('\n')
            public_key_data = ''.join(public_key_lines[1:-1])  # Remove header/footer
            return {
                'name': f'{dkim_key.selector}._domainkey.{domain_name}',
                'type': 'TXT',
                'value': f'v=DKIM1; k=rsa; p={public_key_data}'
            }
        return None

    def sign_email(self, email_content, domain_name):
        """Sign email content with DKIM. Only add one DKIM header, after all modifications."""
        try:
            dkim_key = self.get_active_dkim_key(domain_name)
            if not dkim_key:
                logger.warning(f"No DKIM key found for domain: {domain_name}")
                return email_content
            private_key = dkim_key.private_key
            selector = dkim_key.selector
            # Convert content to bytes if it's a string
            if isinstance(email_content, str):
                email_bytes = email_content.encode('utf-8')
            else:
                email_bytes = email_content
            # Remove any existing DKIM-Signature header (robust multiline)
            import re
            email_bytes = re.sub(br'^DKIM-Signature:.*?(\r?\n[ \t].*?)*\r?\n', b'', email_bytes, flags=re.MULTILINE)
            # Canonicalization: relaxed/relaxed, add more headers to h=
            headers = [
                b'from', b'to', b'subject', b'date', b'message-id',
                b'mime-version', b'content-type', b'content-transfer-encoding'
            ]
            signature = dkim.sign(
                email_bytes,
                selector.encode('utf-8'),
                domain_name.encode('utf-8'),
                private_key.encode('utf-8'),
                include_headers=headers,
                canonicalize=(b'relaxed', b'relaxed')
            )
            signed_content = signature + email_bytes
            logger.debug(f"Successfully signed email for domain: {domain_name} selector: {selector}")
            if isinstance(email_content, str):
                return signed_content.decode('utf-8')
            else:
                return signed_content
        except Exception as e:
            logger.error(f"Error signing email for domain {domain_name}: {e}")
            return email_content
    
    def list_dkim_keys(self):
        """List all DKIM keys."""
        session = Session()
        try:
            keys = session.query(DKIMKey, Domain).join(Domain).all()
            result = []
            
            for dkim_key, domain in keys:
                result.append({
                    'domain': domain.domain_name,
                    'selector': dkim_key.selector,
                    'created_at': dkim_key.created_at,
                    'active': dkim_key.is_active
                })
            
            return result
            
        except Exception as e:
            logger.error(f"Error listing DKIM keys: {e}")
            return []
        finally:
            session.close()
    
    def initialize_default_keys(self):
        """Initialize DKIM keys for existing domains that don't have them."""
        session = Session()
        try:
            domains = session.query(Domain).all()
            for domain in domains:
                existing_key = session.query(DKIMKey).filter_by(
                    domain_id=domain.id, 
                    is_active=True
                ).first()
                
                if not existing_key:
                    logger.debug(f"Generating DKIM key for existing domain: {domain.domain_name}")
                    self.generate_dkim_keypair(domain.domain_name)
                    
        except Exception as e:
            logger.error(f"Error initializing default DKIM keys: {e}")
        finally:
            session.close()

    def get_active_custom_headers(self, domain_name: str) -> list:
        """Get all active custom headers for a domain.

        Args:
            domain_name (str): The domain name.

        Returns:
            list: List of (header_name, header_value) tuples for active headers.
        """
        session = Session()
        try:
            domain = session.query(Domain).filter_by(domain_name=domain_name).first()
            if not domain:
                return []
            headers = session.query(CustomHeader).filter_by(domain_id=domain.id, is_active=True).all()
            return [(h.header_name, h.header_value) for h in headers]
        except Exception as e:
            logger.error(f"Error getting custom headers for {domain_name}: {e}")
            return []
        finally:
            session.close()
