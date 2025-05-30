"""
Authentication modules for the SMTP server.
"""

import logging
from datetime import datetime
from aiosmtpd.smtp import AuthResult, LoginPassword
from models import Session, User, Domain, WhitelistedIP, AuthLog, check_password

logger = logging.getLogger(__name__)

class Authenticator:
    """Username/password authenticator."""
    
    def __call__(self, server, session, envelope, mechanism, auth_data):
        if not isinstance(auth_data, LoginPassword):
            logger.warning(f'Invalid auth data format: {type(auth_data)}')
            return AuthResult(success=False, handled=True, message='535 Authentication failed')
        
        # Decode bytes to string if necessary
        username = auth_data.login
        password = auth_data.password
        
        if isinstance(username, bytes):
            username = username.decode('utf-8')
        if isinstance(password, bytes):
            password = password.decode('utf-8')
            
        session_db = Session()
        
        try:
            peer_ip = session.peer[0]
            logger.debug(f'Authentication attempt: {username} from {peer_ip}')
            
            # Look up user in database
            user = session_db.query(User).filter_by(email=username).first()
            
            if user and check_password(password, user.password_hash):
                domain = session_db.query(Domain).filter_by(id=user.domain_id).first()
                auth_log = AuthLog(
                    timestamp=datetime.now(),
                    peer=str(session.peer),
                    username=username,
                    success=True,
                    message=f'Successful login for {username}'
                )
                session_db.add(auth_log)
                session_db.commit()
                
                logger.info(f'Authenticated user: {username} from domain {domain.domain_name if domain else "unknown"}')
                # Don't include the SMTP response code in the message - let aiosmtpd handle it
                return AuthResult(success=True, handled=True)
            else:
                auth_log = AuthLog(
                    timestamp=datetime.now(),
                    peer=str(session.peer),
                    username=username,
                    success=False,
                    message=f'Failed login for {username}: invalid credentials'
                )
                session_db.add(auth_log)
                session_db.commit()
                
                logger.warning(f'Authentication failed for {username}: invalid credentials')
                return AuthResult(success=False, handled=True, message='535 Authentication failed')
            
        except Exception as e:
            session_db.rollback()
            logger.error(f'Authentication error: {e}')
            return AuthResult(success=False, handled=True, message='451 Internal server error')
        finally:
            session_db.close()

class IPAuthenticator:
    """IP-based authenticator for clients that don't provide credentials."""
    
    def __call__(self, server, session, envelope, mechanism, auth_data):
        session_db = Session()
        try:
            peer_ip = session.peer[0]
            logger.debug(f'IP-based authentication attempt from: {peer_ip}')

            # Check if IP is whitelisted
            whitelist = session_db.query(WhitelistedIP).filter_by(ip_address=peer_ip).first()
            if whitelist:
                domain = session_db.query(Domain).filter_by(id=whitelist.domain_id).first()
                if domain:
                    auth_log = AuthLog(
                        timestamp=datetime.now(),
                        peer=str(session.peer),
                        username=None,
                        success=True,
                        message=f'Authenticated via whitelisted IP for domain {domain.domain_name}'
                    )
                    session_db.add(auth_log)
                    session_db.commit()
                    logger.info(f'Authenticated via whitelist: IP {peer_ip} for {domain.domain_name}')
                    return AuthResult(success=True, handled=True, message='Authenticated via whitelist')
            
            return AuthResult(success=False, handled=True, message='IP not whitelisted')
        except Exception as e:
            session_db.rollback()
            logger.error(f'IP Authentication error: {e}')
            return AuthResult(success=False, handled=True, message='Server error')
        finally:
            session_db.close()
