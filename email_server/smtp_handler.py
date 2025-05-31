"""
SMTP handler for processing incoming emails.
"""

import uuid
from datetime import datetime
from aiosmtpd.smtp import SMTP as AIOSMTP, AuthResult
from aiosmtpd.controller import Controller
from email_server.auth import Authenticator, IPAuthenticator
from email_server.email_relay import EmailRelay
from email_server.dkim_manager import DKIMManager
from email_server.tool_box import get_logger

logger = get_logger()

class CombinedAuthenticator:
    """Combined authenticator that tries username/password first, then falls back to IP whitelist."""
    
    def __init__(self):
        self.user_auth = Authenticator()
        self.ip_auth = IPAuthenticator()
    
    def __call__(self, server, session, envelope, mechanism, auth_data):
        from aiosmtpd.smtp import LoginPassword
        
        # If auth_data is provided (username/password), try user authentication first
        if auth_data and isinstance(auth_data, LoginPassword):
            result = self.user_auth(server, session, envelope, mechanism, auth_data)
            if result.success:
                return result
            # If user auth fails, don't try IP auth - return the failure
            return result
        
        # If no auth_data provided, try IP-based authentication
        return self.ip_auth(server, session, envelope, mechanism, auth_data)

class CustomSMTPHandler:
    """Custom SMTP handler for processing emails."""
    
    def __init__(self):
        self.authenticator = Authenticator()
        self.ip_authenticator = IPAuthenticator()
        self.combined_authenticator = CombinedAuthenticator()
        self.email_relay = EmailRelay()
        self.dkim_manager = DKIMManager()
        self.auth_require_tls = False
        self.auth_methods = ['LOGIN', 'PLAIN']

    def _ensure_required_headers(self, content: str, envelope, message_id: str) -> str:
        """Ensure all required email headers are present.
        
        Args:
            content (str): Email content.
            envelope: SMTP envelope.
            message_id (str): Generated message ID.
            
        Returns:
            str: Email content with all required headers.
        """
        import email.utils
        from datetime import datetime
        
        # Parse existing headers
        lines = content.split('\n')
        headers = {}
        body_start = 0
        
        # Find where headers end and body begins
        for i, line in enumerate(lines):
            if line.strip() == '':
                body_start = i + 1
                break
            if ':' in line and not line.startswith(' ') and not line.startswith('\t'):
                header_name, header_value = line.split(':', 1)
                headers[header_name.strip().lower()] = header_value.strip()
        
        # Extract body
        body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ''
        
        # Build required headers
        required_headers = []
        
        # Add Message-ID if missing
        if 'message-id' not in headers:
            required_headers.append(f"Message-ID: <{message_id}@{envelope.mail_from.split('@')[1] if '@' in envelope.mail_from else 'localhost'}>")
        
        # Add Date if missing
        if 'date' not in headers:
            required_headers.append(f"Date: {email.utils.formatdate(localtime=True)}")
        
        # Add From if missing
        if 'from' not in headers:
            required_headers.append(f"From: {envelope.mail_from}")
        
        # Add To if missing
        if 'to' not in headers:
            to_list = ', '.join(envelope.rcpt_tos)
            required_headers.append(f"To: {to_list}")
        
        # Add MIME-Version if missing
        if 'mime-version' not in headers:
            required_headers.append("MIME-Version: 1.0")
        
        # Add Content-Type if missing
        if 'content-type' not in headers:
            required_headers.append("Content-Type: text/plain; charset=utf-8")
        
        # Rebuild the email with required headers first, then existing headers, then body
        new_content_lines = required_headers
        
        # Add existing headers (excluding the ones we just added)
        for i in range(body_start):
            line = lines[i]
            if ':' in line and not line.startswith(' ') and not line.startswith('\t'):
                header_name = line.split(':', 1)[0].strip().lower()
                if header_name not in ['message-id', 'date', 'from', 'to', 'mime-version', 'content-type']:
                    new_content_lines.append(line)
            elif line.startswith(' ') or line.startswith('\t'):
                # Continuation of previous header
                new_content_lines.append(line)
        
        # Add empty line between headers and body
        new_content_lines.append('')
        
        # Add body
        new_content_lines.append(body)
        
        return '\r\n'.join(new_content_lines)

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
        """Handle MAIL FROM command - validate sender."""
        logger.debug(f'MAIL FROM: {address}')
        envelope.mail_from = address
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
