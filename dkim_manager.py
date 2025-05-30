"""
DKIM key management and email signing functionality.
"""

import logging
import dkim
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime
from models import Session, Domain, DKIMKey
from config import DKIM_SELECTOR, DKIM_KEY_SIZE

logger = logging.getLogger(__name__)

class DKIMManager:
    """Manages DKIM keys and email signing."""
    
    def __init__(self):
        self.selector = DKIM_SELECTOR
    
    def generate_dkim_keypair(self, domain_name):
        """Generate DKIM key pair for a domain."""
        session = Session()
        try:
            # Check if domain exists
            domain = session.query(Domain).filter_by(domain_name=domain_name).first()
            if not domain:
                logger.error(f"Domain {domain_name} not found")
                return False
            
            # Check if DKIM key already exists
            existing_key = session.query(DKIMKey).filter_by(domain_id=domain.id, is_active=True).first()
            if existing_key:
                logger.info(f"DKIM key already exists for domain {domain_name}")
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
                selector=self.selector,
                private_key=private_pem,
                public_key=public_pem,
                created_at=datetime.now(),
                is_active=True
            )
            session.add(dkim_key)
            session.commit()
            
            logger.info(f"Generated DKIM key for domain: {domain_name}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Error generating DKIM key for {domain_name}: {e}")
            return False
        finally:
            session.close()
    
    def get_dkim_private_key(self, domain_name):
        """Get DKIM private key for a domain."""
        session = Session()
        try:
            domain = session.query(Domain).filter_by(domain_name=domain_name).first()
            if not domain:
                return None
            
            dkim_key = session.query(DKIMKey).filter_by(
                domain_id=domain.id, 
                is_active=True
            ).first()
            
            if dkim_key:
                return dkim_key.private_key
            return None
            
        except Exception as e:
            logger.error(f"Error getting DKIM private key for {domain_name}: {e}")
            return None
        finally:
            session.close()
    
    def get_dkim_public_key_record(self, domain_name):
        """Get DKIM public key DNS record for a domain."""
        session = Session()
        try:
            domain = session.query(Domain).filter_by(domain_name=domain_name).first()
            if not domain:
                return None
            
            dkim_key = session.query(DKIMKey).filter_by(
                domain_id=domain.id, 
                is_active=True
            ).first()
            
            if dkim_key:
                # Extract public key from PEM format for DNS record
                public_key_lines = dkim_key.public_key.strip().split('\n')
                public_key_data = ''.join(public_key_lines[1:-1])  # Remove header/footer
                
                return {
                    'name': f'{self.selector}._domainkey.{domain_name}',
                    'type': 'TXT',
                    'value': f'v=DKIM1; k=rsa; p={public_key_data}'
                }
            return None
            
        except Exception as e:
            logger.error(f"Error getting DKIM public key record for {domain_name}: {e}")
            return None
        finally:
            session.close()
    
    def sign_email(self, email_content, domain_name):
        """Sign email content with DKIM."""
        try:
            private_key = self.get_dkim_private_key(domain_name)
            if not private_key:
                logger.warning(f"No DKIM key found for domain: {domain_name}")
                return email_content
            
            # Convert content to bytes if it's a string
            if isinstance(email_content, str):
                email_bytes = email_content.encode('utf-8')
            else:
                email_bytes = email_content
            
            # Sign the email
            signature = dkim.sign(
                email_bytes,
                self.selector.encode('utf-8'),
                domain_name.encode('utf-8'),
                private_key.encode('utf-8'),
                include_headers=[b'from', b'to', b'subject', b'date', b'message-id']
            )
            
            # Combine signature with original content
            signed_content = signature + email_bytes
            
            logger.info(f"Successfully signed email for domain: {domain_name}")
            
            # Return as string if input was string
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
                    logger.info(f"Generating DKIM key for existing domain: {domain.domain_name}")
                    self.generate_dkim_keypair(domain.domain_name)
                    
        except Exception as e:
            logger.error(f"Error initializing default DKIM keys: {e}")
        finally:
            session.close()
