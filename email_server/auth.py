"""
Enhanced authentication modules for the SMTP server using ESRV schema.

Security Features:
- Users can only send as their own email or domain emails (if permitted)
- IP authentication is domain-specific  
- Comprehensive audit logging
- Enhanced validation and error handling
"""

from datetime import datetime
from aiosmtpd.smtp import AuthResult, LoginPassword
from email_server.models import (
    Session, User, Domain, WhitelistedIP, 
    check_password, log_auth_attempt, get_user_by_email, 
    get_whitelisted_ip, get_domain_by_name
)
from email_server.tool_box import get_logger

logger = get_logger()

class EnhancedAuthenticator:
    """
    Enhanced username/password authenticator with sender validation.
    
    Features:
    - Validates user credentials
    - Stores authenticated user info for sender validation
    - Comprehensive audit logging
    """
    
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
        
        peer_ip = session.peer[0]
        logger.debug(f'Authentication attempt: {username} from {peer_ip}')
        
        try:
            # Look up user in database
            user = get_user_by_email(username)
            
            if user and check_password(password, user.password_hash):
                # Store authenticated user info in session for later validation
                session.authenticated_user = user
                session.auth_type = 'user'
                
                # Log successful authentication
                log_auth_attempt(
                    auth_type='user',
                    identifier=username,
                    ip_address=peer_ip,
                    success=True,
                    message=f'Successful user authentication'
                )
                
                logger.info(f'Authenticated user: {username} (ID: {user.id}, can_send_as_domain: {user.can_send_as_domain})')
                return AuthResult(success=True, handled=True)
            else:
                # Log failed authentication
                log_auth_attempt(
                    auth_type='user',
                    identifier=username,
                    ip_address=peer_ip,
                    success=False,
                    message=f'Invalid credentials for {username}'
                )
                
                logger.warning(f'Authentication failed for {username}: invalid credentials')
                return AuthResult(success=False, handled=True, message='535 Authentication failed')
            
        except Exception as e:
            logger.error(f'Authentication error for {username}: {e}')
            log_auth_attempt(
                auth_type='user',
                identifier=username,
                ip_address=peer_ip,
                success=False,
                message=f'Authentication error: {str(e)}'
            )
            return AuthResult(success=False, handled=True, message='451 Internal server error')

class EnhancedIPAuthenticator:
    """
    Enhanced IP-based authenticator with domain-specific authorization.
    
    Features:
    - Domain-specific IP authentication
    - Only allows sending for authorized domain
    - Comprehensive audit logging
    """
    
    def can_authenticate_for_domain(self, ip_address: str, domain_name: str) -> tuple[bool, str]:
        """
        Check if IP can authenticate for a specific domain.
        
        Args:
            ip_address: Client IP address
            domain_name: Domain to check authorization for
            
        Returns:
            (success, message) tuple
        """
        try:
            whitelisted_ip = get_whitelisted_ip(ip_address, domain_name)
            if whitelisted_ip:
                return True, f"IP {ip_address} authorized for domain {domain_name}"
            else:
                return False, f"IP {ip_address} not authorized for domain {domain_name}"
        except Exception as e:
            logger.error(f"Error checking IP authorization: {e}")
            return False, f"Error checking IP authorization: {str(e)}"

def validate_sender_authorization(session, mail_from: str) -> tuple[bool, str]:
    """
    Validate if the authenticated entity can send as the specified from address.
    
    Args:
        session: SMTP session with authentication info
        mail_from: The MAIL FROM address
        
    Returns:
        (authorized, message) tuple
    """
    if not mail_from:
        return False, "No sender address provided"
    
    # Extract domain from mail_from
    try:
        from_domain = mail_from.split('@')[1].lower() if '@' in mail_from else ''
        if not from_domain:
            return False, "Invalid sender address format"
    except (IndexError, AttributeError):
        return False, "Invalid sender address format"
    
    peer_ip = session.peer[0]
    
    # Check user authentication
    if hasattr(session, 'authenticated_user') and session.authenticated_user:
        user = session.authenticated_user
        
        if user.can_send_as(mail_from):
            logger.info(f"User {user.email} authorized to send as {mail_from}")
            return True, f"User authorized to send as {mail_from}"
        else:
            message = f"User {user.email} not authorized to send as {mail_from}"
            logger.warning(message)
            log_auth_attempt(
                auth_type='sender_validation',
                identifier=f"{user.email} -> {mail_from}",
                ip_address=peer_ip,
                success=False,
                message=message
            )
            return False, message
    
    # Check IP authentication for domain
    authenticator = EnhancedIPAuthenticator()
    can_auth, auth_message = authenticator.can_authenticate_for_domain(peer_ip, from_domain)
    
    if can_auth:
        # Store IP auth info in session
        session.auth_type = 'ip'
        session.authorized_domain = from_domain
        
        log_auth_attempt(
            auth_type='ip',
            identifier=f"{peer_ip} -> {from_domain}",
            ip_address=peer_ip,
            success=True,
            message=f"IP authorized for domain {from_domain}"
        )
        
        logger.info(f"IP {peer_ip} authorized to send for domain {from_domain}")
        return True, f"IP authorized for domain {from_domain}"
    else:
        log_auth_attempt(
            auth_type='ip',
            identifier=f"{peer_ip} -> {from_domain}",
            ip_address=peer_ip,
            success=False,
            message=auth_message
        )
        
        logger.warning(f"IP {peer_ip} not authorized for domain {from_domain}: {auth_message}")
        return False, f"Not authorized to send for domain {from_domain}"

def get_authenticated_domain_id(session) -> int:
    """
    Get the domain ID for the authenticated entity.
    
    Args:
        session: SMTP session with authentication info
        
    Returns:
        Domain ID or None if not authenticated
    """
    if hasattr(session, 'authenticated_user') and session.authenticated_user:
        return session.authenticated_user.domain_id
    
    if hasattr(session, 'authorized_domain') and session.authorized_domain:
        domain = get_domain_by_name(session.authorized_domain)
        return domain.id if domain else None
    
    return None
