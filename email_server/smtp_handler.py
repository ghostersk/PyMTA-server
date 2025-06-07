"""
Enhanced SMTP handler for processing incoming emails with security controls.

Security Features:
- Users can only send as their own email or domain emails (if permitted)
- IP authentication is domain-specific
- Sender authorization validation
- Enhanced header management
"""

import uuid
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

    def _ensure_required_headers(self, content: str, envelope, message_id: str, custom_headers: list = None) -> str:
        """Ensure all required email headers are present and properly formatted.
        
        Following RFC 5322 header order and best practices for spam score reduction.
        Optimized based on Gmail's header structure for better deliverability.
        
        Args:
            content (str): Email content.
            envelope: SMTP envelope.
            message_id (str): Generated message ID.
            custom_headers (list): List of (name, value) tuples for custom headers.
            
        Returns:
            str: Email content with all required headers properly formatted.
        """
        import email.utils
        from email_server.settings_loader import load_settings
        
        try:
            settings = load_settings()
            server_hostname = settings.get('Server', 'helo_hostname', fallback='mail.netbro.uk')
            
            logger.debug(f"Processing headers for message {message_id}")
            
            # Parse the message properly
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='replace')
            
            # Split content into lines and normalize line endings
            lines = content.replace('\r\n', '\n').replace('\r', '\n').split('\n')
            
            # Find header/body boundary and collect existing headers
            body_start = 0
            existing_headers = {}
            original_header_order = []
            
            for i, line in enumerate(lines):
                if line.strip() == '':
                    body_start = i + 1
                    break
                if ':' in line and not line.startswith((' ', '\t')):
                    header_name, header_value = line.split(':', 1)
                    header_name_lower = header_name.strip().lower()
                    header_value = header_value.strip()
                    
                    # Handle continuation lines
                    j = i + 1
                    while j < len(lines) and lines[j].startswith((' ', '\t')):
                        header_value += ' ' + lines[j].strip()
                        j += 1
                    
                    existing_headers[header_name_lower] = header_value
                    original_header_order.append((header_name.strip(), header_value))
                    logger.debug(f"Found existing header: {header_name_lower} = {header_value}")
            
            # Extract body and clean it
            body_lines = lines[body_start:] if body_start < len(lines) else []
            while body_lines and body_lines[-1].strip() == '':
                body_lines.pop()
            body = '\n'.join(body_lines)
            
            # Build headers in optimized order based on Gmail's structure
            required_headers = []
            
            # 1. Message-ID (critical for spam filters)
            if 'message-id' in existing_headers:
                required_headers.append(f"Message-ID: {existing_headers['message-id']}")
            else:
                domain = envelope.mail_from.split('@')[1] if '@' in envelope.mail_from else server_hostname.replace('mail.', '')
                required_headers.append(f"Message-ID: <{message_id}@{domain}>")
            
            # 2. Date (critical for spam filters)
            if 'date' in existing_headers:
                required_headers.append(f"Date: {existing_headers['date']}")
            else:
                date_str = email.utils.formatdate(localtime=True)
                required_headers.append(f"Date: {date_str}")
            
            # 3. MIME-Version (declare MIME compliance early)
            if 'mime-version' in existing_headers:
                required_headers.append(f"MIME-Version: {existing_headers['mime-version']}")
            else:
                required_headers.append("MIME-Version: 1.0")
            
            # 4. User-Agent (if present, helps with reputation)
            if 'user-agent' in existing_headers:
                required_headers.append(f"User-Agent: {existing_headers['user-agent']}")
            
            # 5. Content-Language (if present)
            if 'content-language' in existing_headers:
                required_headers.append(f"Content-Language: {existing_headers['content-language']}")
            
            # 6. To (primary recipients - critical)
            if 'to' in existing_headers:
                required_headers.append(f"To: {existing_headers['to']}")
            else:
                to_list = ', '.join(envelope.rcpt_tos)
                required_headers.append(f"To: {to_list}")
            
            # 7. From (sender identification - critical)
            if 'from' in existing_headers:
                required_headers.append(f"From: {existing_headers['from']}")
            else:
                required_headers.append(f"From: {envelope.mail_from}")
            
            # 8. Subject (message topic - critical)
            if 'subject' in existing_headers:
                required_headers.append(f"Subject: {existing_headers['subject']}")
            else:
                required_headers.append("Subject: ")
            
            # 9. Content-Type (media type information)
            if 'content-type' in existing_headers:
                required_headers.append(f"Content-Type: {existing_headers['content-type']}")
            else:
                required_headers.append("Content-Type: text/plain; charset=UTF-8; format=flowed")
            
            # 10. Content-Transfer-Encoding
            if 'content-transfer-encoding' in existing_headers:
                required_headers.append(f"Content-Transfer-Encoding: {existing_headers['content-transfer-encoding']}")
            else:
                required_headers.append("Content-Transfer-Encoding: 7bit")
            
            # Add custom headers after essential headers but before misc headers
            if custom_headers:
                for header_name, header_value in custom_headers:
                    # Skip if already added in essential headers
                    if header_name.lower() not in ['message-id', 'date', 'mime-version', 'user-agent',
                                                  'content-language', 'to', 'from', 'subject', 
                                                  'content-type', 'content-transfer-encoding']:
                        required_headers.append(f"{header_name}: {header_value}")
                        logger.debug(f"Added custom header: {header_name}: {header_value}")
            
            # Add any other existing headers that weren't handled above
            essential_headers = {
                'message-id', 'date', 'from', 'to', 'subject', 
                'mime-version', 'content-type', 'content-transfer-encoding',
                'user-agent', 'content-language'
            }
            
            # Preserve original header names and values for non-essential headers
            for header_name, header_value in original_header_order:
                if header_name.lower() not in essential_headers:
                    # Skip custom headers we already added
                    skip = False
                    if custom_headers:
                        for custom_name, _ in custom_headers:
                            if header_name.lower() == custom_name.lower():
                                skip = True
                                break
                    if not skip:
                        required_headers.append(f"{header_name}: {header_value}")
            
            # Build final message
            final_content = '\r\n'.join(required_headers)
            if body.strip():
                final_content += '\r\n\r\n' + body
            else:
                final_content += '\r\n\r\n'
            
            logger.debug(f"Final headers for message {message_id}:")
            for header in required_headers:
                logger.debug(f"  {header}")
            
            return final_content
            
        except Exception as e:
            logger.error(f"Error ensuring headers: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            # Fallback to original content if parsing fails
            return content

    async def handle_DATA(self, server, session, envelope):
        """Handle incoming email data with improved header management."""
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
            
            # Get custom headers before processing
            custom_headers = []
            if sender_domain:
                custom_headers = self.dkim_manager.get_active_custom_headers(sender_domain)
            
            # Add beneficial headers for spam score improvement
            client_ip = getattr(session, 'peer', ['unknown'])[0] if hasattr(session, 'peer') else None
            if client_ip:
                # Add X-Originating-IP header (helps with reputation)
                custom_headers.append(('X-Originating-IP', f'[{client_ip}]'))
            
            # Add X-Mailer header for identification
            custom_headers.append(('X-Mailer', 'NetBro Mail Server 1.0'))
            
            # Add X-Priority header (normal priority)
            custom_headers.append(('X-Priority', '3'))
            
            # Ensure required headers are present (including custom headers)
            content = self._ensure_required_headers(content, envelope, message_id, custom_headers)
            
            # DKIM-sign the final version of the message (only once, after all modifications)
            signed_content = content
            dkim_signed = False
            if sender_domain:
                signed_content = self.dkim_manager.sign_email(content, sender_domain)
                dkim_signed = signed_content != content
                if dkim_signed:
                    logger.debug(f'Email {message_id} signed with DKIM for domain {sender_domain}')
            
            # Relay the email (no further modifications allowed)
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
        logger.debug(f"TLSController __init__: ssl_context={ssl_context is not None}")
        self._ssl_context = ssl_context  # Use private attribute to avoid conflicts
        self.smtp_hostname = hostname  # Store for HELO identification
        super().__init__(handler, hostname='0.0.0.0', port=port)  # Bind to all interfaces
    
    def factory(self):
        logger.debug(f"TLSController factory: ssl_context={self._ssl_context is not None}")
        logger.debug(f"TLSController factory: ssl_context object={self._ssl_context}")
        logger.debug(f"TLSController factory: hostname={self.smtp_hostname}")
        smtp_instance = AIOSMTP(
            self.handler,
            tls_context=self._ssl_context,
            require_starttls=False,  # Don't require STARTTLS immediately, but make it available
            auth_require_tls=True,   # If auth is used, require TLS
            authenticator=self.handler.combined_authenticator,
            decode_data=True,
            hostname=self.smtp_hostname  # Use proper hostname for HELO
        )
        logger.debug(f"TLSController AIOSMTP instance created with TLS: {hasattr(smtp_instance, 'tls_context')}")
        return smtp_instance

class PlainController(Controller):
    """Controller for plain SMTP with username/password and IP-based authentication."""
    
    def __init__(self, handler, hostname='localhost', port=4025):
        self.smtp_hostname = hostname  # Store for HELO identification
        super().__init__(handler, hostname='0.0.0.0', port=port)  # Bind to all interfaces
    
    def factory(self):
        return AIOSMTP(
            self.handler,
            authenticator=self.handler.combined_authenticator,
            auth_require_tls=False,  # Allow AUTH over plain text (not recommended for production)
            decode_data=True,
            hostname=self.smtp_hostname  # Use proper hostname for HELO
        )
