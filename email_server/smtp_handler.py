"""
Enhanced SMTP handler for processing incoming emails with security controls.

Security Features:
- Users can only send as their own email or domain emails (if permitted)
- IP authentication is domain-specific
- Sender authorization validation
- Enhanced header management
"""

import uuid
import email.utils
from datetime import datetime
from aiosmtpd.smtp import SMTP as AIOSMTP, AuthResult
from aiosmtpd.controller import Controller
from email_server.auth import EnhancedAuthenticator, EnhancedIPAuthenticator, validate_sender_authorization, get_authenticated_domain_id
from email_server.email_relay import EmailRelay
from email_server.dkim_manager import DKIMManager
from email_server.tool_box import get_logger

logger = get_logger()

class EnhancedCombinedAuthenticator:
    """
    Enhanced combined authenticator with sender validation support.
    
    Features:
    - User authentication with session storage
    - IP-based authentication with domain validation  
    - Fallback authentication logic
    """
    
    def __init__(self):
        self.user_auth = EnhancedAuthenticator()
        self.ip_auth = EnhancedIPAuthenticator()
    
    def __call__(self, server, session, envelope, mechanism, auth_data):
        from aiosmtpd.smtp import LoginPassword
        
        # If auth_data is provided (username/password), try user authentication first
        if auth_data and isinstance(auth_data, LoginPassword):
            result = self.user_auth(server, session, envelope, mechanism, auth_data)
            if result.success:
                return result
            # If user auth fails, don't try IP auth - return the failure
            return result
        
        # If no auth_data provided, IP auth will be validated during MAIL FROM
        # For now, allow the connection to proceed
        return AuthResult(success=True, handled=True)

class EnhancedCustomSMTPHandler:
    """Enhanced custom SMTP handler with security controls."""
    
    def __init__(self):
        self.authenticator = EnhancedAuthenticator()
        self.ip_authenticator = EnhancedIPAuthenticator()
        self.combined_authenticator = EnhancedCombinedAuthenticator()
        self.email_relay = EmailRelay()
        self.dkim_manager = DKIMManager()
        self.auth_require_tls = False
        self.auth_methods = ['LOGIN', 'PLAIN']

    def _ensure_required_headers(self, content: str, envelope, message_id: str) -> str:
        """Ensure all required email headers are present and properly formatted.

        Args:
            content (str): Email content.
            envelope: SMTP envelope.
            message_id (str): Generated message ID.

        Returns:
            str: Email content with all required headers.
        """
        import email
        from email.parser import Parser
        from email.policy import default

        # Parse the message using the email library
        msg = Parser(policy=default).parsestr(content)

        # Set or add required headers if missing
        if not msg.get('Message-ID'):
            msg['Message-ID'] = f"<{message_id}@{envelope.mail_from.split('@')[1] if '@' in envelope.mail_from else 'localhost'}>"
        if not msg.get('Date'):
            msg['Date'] = email.utils.formatdate(localtime=True)
        if not msg.get('From'):
            msg['From'] = envelope.mail_from
        if not msg.get('To'):
            msg['To'] = ', '.join(envelope.rcpt_tos)
        if not msg.get('MIME-Version'):
            msg['MIME-Version'] = '1.0'
        if not msg.get('Content-Type'):
            msg['Content-Type'] = 'text/plain; charset=utf-8'
        if not msg.get('Subject'):
            msg['Subject'] = '(No Subject)'
        if not msg.get('Content-Transfer-Encoding'):
            msg['Content-Transfer-Encoding'] = '7bit'

        # Ensure exactly one blank line between headers and body
        # The email library will handle this when flattening
        from io import StringIO
        out = StringIO()
        out.write(msg.as_string())
        return out.getvalue()

    async def handle_DATA(self, server, session, envelope):
        """Handle incoming email data."""
        try:
            message_id = str(uuid.uuid4())
            logger.debug(f'Received email {message_id} from {envelope.mail_from} to {envelope.rcpt_tos}')
            
            # Convert content to string if it's bytes
            if isinstance(envelope.content, bytes):
                content = envelope.content.decode('utf-8', errors='replace')
            else:
                content = envelope.content
            
            # Extract domain from sender for DKIM signing
            sender_domain = envelope.mail_from.split('@')[1] if '@' in envelope.mail_from else None
            
            # Ensure required headers are present
            content = self._ensure_required_headers(content, envelope, message_id)
            
            # Add custom headers before DKIM signing
            if sender_domain:
                custom_headers = self.dkim_manager.get_active_custom_headers(sender_domain)
                for header_name, header_value in custom_headers:
                    # Insert header at the top of the message
                    content = f"{header_name}: {header_value}\r\n" + content
            
            # Relay the email (all modifications done)
            signed_content = content
            dkim_signed = False
            if sender_domain:
                # DKIM-sign the final version of the message
                signed_content = self.dkim_manager.sign_email(content, sender_domain)
                dkim_signed = signed_content != content
                if dkim_signed:
                    logger.debug(f'Email {message_id} signed with DKIM for domain {sender_domain}')
            
            success = self.email_relay.relay_email(
                envelope.mail_from, 
                envelope.rcpt_tos, 
                signed_content
            )
            
            # Log the email
            status = 'relayed' if success else 'failed'
            self.email_relay.log_email(
                message_id=message_id,
                peer=session.peer,
                mail_from=envelope.mail_from,
                rcpt_tos=envelope.rcpt_tos,
                content=content,  # Log original content, not signed
                status=status,
                dkim_signed=dkim_signed
            )
            
            if success:
                logger.debug(f'Email {message_id} successfully relayed')
                return '250 Message accepted for delivery'
            else:
                logger.error(f'Email {message_id} failed to relay')
                return '550 Message relay failed'
                
        except Exception as e:
            logger.error(f'Error handling email: {e}')
            return '550 Internal server error'

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        """Handle RCPT TO command - validate recipients."""
        logger.debug(f'RCPT TO: {address}')
        envelope.rcpt_tos.append(address)
        return '250 OK'

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        """
        Handle MAIL FROM command with enhanced sender validation.
        
        Security Features:
        - Validates user can send as the specified address
        - Validates IP authorization for domain
        - Comprehensive audit logging
        """
        logger.debug(f'MAIL FROM: {address}')
        
        # Validate sender authorization
        authorized, message = validate_sender_authorization(session, address)
        
        if not authorized:
            logger.warning(f'MAIL FROM rejected: {address} - {message}')
            return f'550 {message}'
        
        envelope.mail_from = address
        logger.info(f'MAIL FROM accepted: {address} - {message}')
        return '250 OK'

class TLSController(Controller):
    """Custom controller with TLS support - modeled after the working original."""
    
    def __init__(self, handler, ssl_context, hostname='localhost', port=40587):
        self.ssl_context = ssl_context
        super().__init__(handler, hostname=hostname, port=port)
    
    def factory(self):
        return AIOSMTP(
            self.handler,
            tls_context=self.ssl_context,
            require_starttls=True,  # Don't force STARTTLS, but make it available
            auth_require_tls=True,   # If auth is used, require TLS
            authenticator=self.handler.combined_authenticator,
            decode_data=True,
            hostname=self.hostname
        )

class PlainController(Controller):
    """Controller for plain SMTP with username/password and IP-based authentication."""
    
    def factory(self):
        return AIOSMTP(
            self.handler,
            authenticator=self.handler.combined_authenticator,
            auth_require_tls=False,  # Allow AUTH over plain text (not recommended for production)
            decode_data=True,
            hostname=self.hostname
        )
