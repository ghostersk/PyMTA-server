"""
Enhanced SMTP handler for processing incoming emails with security controls.

Security Features:
- Users can only send as their own email or domain emails (if permitted)
- IP authentication is domain-specific
- Sender authorization validation
- Enhanced header management
"""

import email.utils
import os
import mimetypes
from aiosmtpd.smtp import SMTP as AIOSMTP, AuthResult
from aiosmtpd.controller import Controller
from email_server.auth import EnhancedAuthenticator, EnhancedIPAuthenticator, validate_sender_authorization
from email_server.email_relay import EmailRelay
from email_server.dkim_manager import DKIMManager
from email_server.settings_loader import load_settings
from email_server.tool_box import get_logger, ensure_folder_exists, generate_message_id, get_current_time
from email import policy
from email.parser import BytesParser
from email_server.models import Session, EmailAttachment, EmailLog

logger = get_logger()
settings = load_settings()

helo_hostname = settings['Server'].get('helo_hostname', settings['Server'].get('hostname', 'localhost'))

class CustomSMTP(AIOSMTP):
    """Custom SMTP class with configurable banner and secure AUTH handling."""
    
    def __init__(self, *args, **kwargs):
        # Sets Custom SMTP banner from settings
        _banner_message = settings['Server'].get('server_banner', '')
        if _banner_message == '""':
            _banner_message = ''
        self.custom_banner = _banner_message
        
        # Store authenticator and auth_require_tls for later use
        self._custom_authenticator = kwargs.get('authenticator', None)
        self._custom_auth_require_tls = kwargs.get('auth_require_tls', False)
        super().__init__(*args, **kwargs)
        # Override the __ident__ to use our custom banner
        self.__ident__ = self.custom_banner

    def _get_auth_methods(self):
        # Only advertise AUTH if authenticator is set and (not auth_require_tls or connection is secure)
        if self._custom_authenticator and (not self._custom_auth_require_tls or self.session and self.session.ssl):
            return super()._get_auth_methods()
        return []

    async def smtp_AUTH(self, arg):
        """
        Override AUTH command to close connection after failed authentication.
        """
        result = await super().smtp_AUTH(arg)
        # If authentication failed, close the connection immediately
        if isinstance(result, AuthResult) and not result.success:
            if hasattr(self, 'session') and hasattr(self.session, 'transport') and self.session.transport:
                self.session.transport.close()
        return result

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
        """Ensure all required email headers are present and properly formatted."""
        try:
            lines = content.splitlines()
            for idx, line in enumerate(lines):
                if not isinstance(line, str):
                    logger.error(f"_ensure_required_headers: Non-string line at index {idx}: {type(line)}: {line}")
                    logger.error(f"_ensure_required_headers: Full content object: {repr(content)}")
                    raise TypeError(f"_ensure_required_headers: Non-string line in content.splitlines(): {type(line)} at index {idx}")
            # Find header/body boundary and collect existing headers
            body_start = 0
            existing_headers = {}
            original_header_order = []
            for i, line in enumerate(lines):
                if line.strip() == '':
                    body_start = i + 1
                    break
                if not isinstance(line, str):
                    logger.error(f"_ensure_required_headers: Header line is not a string: {type(line)}: {line}")
                    continue
                if ':' in line and not line.startswith((' ', '\t')):
                    try:
                        header_name, header_value = line.split(':', 1)
                    except Exception as e:
                        logger.error(f"_ensure_required_headers: Failed to split header line: {line} - {e}")
                        continue
                    if not isinstance(header_name, str) or not isinstance(header_value, str):
                        logger.error(f"_ensure_required_headers: Non-string header_name or header_value: {type(header_name)}, {type(header_value)}: {header_name}, {header_value}")
                        continue
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
                # Parse existing Message-ID
                existing_msg_id = existing_headers['message-id'].strip('<>')
                if '@' in existing_msg_id:
                    prefix, hostname = existing_msg_id.rsplit('@', 1)
                    hostname = hostname.rstrip('>')
                    if hostname.lower() != helo_hostname.lower():
                        # If hostname is wrong, modify it to use our hostname
                        message_id = f"{prefix}@{helo_hostname}"
                    else:
                        # If hostname is correct, keep original ID
                        message_id = existing_msg_id
                else:
                    # Malformed Message-ID, generate new one
                    message_id = generate_message_id()
            else:
                # No Message-ID found, generate new one
                message_id = generate_message_id()
            
            # Add the Message-ID header with the final ID
            required_headers.append(f"Message-ID: <{message_id}>")
            
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
            
            # 4. To (primary recipients - critical)
            if 'to' in existing_headers:
                required_headers.append(f"To: {existing_headers['to']}")
            else:
                required_headers.append(f"To: {', '.join([rcpt for rcpt in envelope.rcpt_tos])}")

            # 5. Cc (if present)
            if 'cc' in existing_headers:
                required_headers.append(f"Cc: {existing_headers['cc']}")
            
            # 6. From (sender identification - critical)
            if 'from' in existing_headers:
                required_headers.append(f"From: {existing_headers['from']}")
            else:
                required_headers.append(f"From: {envelope.mail_from}")
            
            # 7. Subject (message topic - critical)
            if 'subject' in existing_headers:
                required_headers.append(f"Subject: {existing_headers['subject']}")
            else:
                required_headers.append("Subject: ")
            
            # 8. Content-Type (media type information)
            if 'content-type' in existing_headers:
                required_headers.append(f"Content-Type: {existing_headers['content-type']}")
            else:
                required_headers.append("Content-Type: text/plain; charset=UTF-8; format=flowed")
            
            # 9. Content-Transfer-Encoding
            if 'content-transfer-encoding' in existing_headers:
                required_headers.append(f"Content-Transfer-Encoding: {existing_headers['content-transfer-encoding']}")
            else:
                required_headers.append("Content-Transfer-Encoding: 7bit")

            # Add custom headers after essential headers
            if custom_headers:
                for header_name, header_value in custom_headers:
                    header_name_lower = header_name.lower()
                    # Skip if header already exists
                    if header_name_lower not in existing_headers:
                        required_headers.append(f"{header_name}: {header_value}")
                        logger.debug(f"Added custom header: {header_name}: {header_value}")

            # Build final message
            final_content = '\r\n'.join(required_headers)
            if body.strip():
                final_content += '\r\n\r\n' + body
            else:
                final_content += '\r\n\r\n'
            
            return final_content
            
        except Exception as e:
            import traceback
            logger.error(f"Error ensuring headers: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            logger.error(f"Locals: {locals()}")
            # Fallback to original content if parsing fails
            return content

    async def handle_DATA(self, server, session, envelope):
        """Handle incoming email data with improved header management and logging."""
        try:
            # Convert content to string if it's bytes
            if isinstance(envelope.content, bytes):
                content = envelope.content.decode('utf-8', errors='replace')
            else:
                content = envelope.content

            # Extract Message-ID from the content
            for line in content.splitlines():
                if line.lower().startswith('message-id:'):
                    message_id_extracted = line[11:].strip().strip('<>')  # Remove "Message-ID:" and brackets
                    if '@' in message_id_extracted:
                        prefix, hostname = message_id_extracted.rsplit('@', 1)
                        hostname = hostname.rstrip('>')
                    if hostname.lower() != helo_hostname.lower():
                        # If hostname is wrong, modify it to use our hostname
                        message_id = f"{prefix}@{helo_hostname}"
                    else:
                        # If hostname is correct, keep original ID
                        message_id = message_id_extracted
                    break
           
            logger.debug(f'Processing email with ID: {message_id} from {envelope.mail_from} to {envelope.rcpt_tos}')

            # Get authenticated username from session
            username = getattr(session, 'username', None)
            if not username:
                # Check if IP authentication was used
                client_ip = getattr(session, 'peer', ['unknown'])[0].split(':')[0] if hasattr(session, 'peer') else None
                if client_ip:
                    from email_server.models import get_whitelisted_ip
                    sender_domain = envelope.mail_from.split('@')[1] if '@' in envelope.mail_from else None
                    ip_auth = get_whitelisted_ip(client_ip, sender_domain)
                    if ip_auth:
                        username = f"IP:{client_ip}"
            
            logger.debug(f'Authenticated username: {username}')

            # Convert content to string if it's bytes
            if isinstance(envelope.content, bytes):
                content = envelope.content.decode('utf-8', errors='replace')
                raw_bytes = envelope.content
            else:
                content = envelope.content
                raw_bytes = envelope.content.encode('utf-8', errors='replace')

            # Extract domain from sender for DKIM signing
            sender_domain = envelope.mail_from.split('@')[1] if '@' in envelope.mail_from else None

            # Get custom headers before processing
            custom_headers = []
            if sender_domain:
                custom_headers = self.dkim_manager.get_active_custom_headers(sender_domain)

            # Add beneficial headers for spam score improvement
            client_ip = getattr(session, 'peer', ['unknown'])[0] if hasattr(session, 'peer') else None
            if client_ip:
                custom_headers.append(('X-Originating-IP', f'[{client_ip}]'))
            custom_headers.append(('X-Mailer', 'NetBro Mail Server 1.0'))
            custom_headers.append(('X-Priority', '3'))

            # Ensure required headers are present (including custom headers)
            content = self._ensure_required_headers(content, envelope, message_id, custom_headers)

            # DKIM-sign the final version of the message (only once, after all modifications)
            signed_content = content
            dkim_signed = False
            if sender_domain:
                signed_content = self.dkim_manager.sign_email(content, sender_domain)
                if not isinstance(signed_content, (str, bytes)):
                    logger.error(f"DKIMManager.sign_email returned non-str/bytes: {type(signed_content)}: {signed_content}")
                    raise TypeError(f"DKIMManager.sign_email returned non-str/bytes: {type(signed_content)}")
                dkim_signed = signed_content != content
                if dkim_signed:
                    logger.debug(f'Email {message_id} signed with DKIM for domain {sender_domain}')

            # Extract headers for logging
            to_address = ''
            cc_addresses = ''
            bcc_addresses = ''
            subject = ''
            split_lines = content.splitlines()
            for idx, line in enumerate(split_lines):
                if not isinstance(line, str):
                    logger.error(f"DIAGNOSTIC: Non-string line at index {idx}: {type(line)}: {line}")
                    logger.error(f"DIAGNOSTIC: Full content object: {repr(content)}")
                    raise TypeError(f"DIAGNOSTIC: Non-string line in content.splitlines(): {type(line)} at index {idx}")
            try:

                for line in split_lines:
                    if line.strip() == '':
                        break
                    if not isinstance(line, str):
                        logger.error(f"Header line is not a string: {type(line)}: {line}")
                        continue
                    try:
                        lower_line = line.lower()
                    except Exception as e:
                        logger.error(f"Failed to call lower() on line: {line} (type: {type(line)}) - {e}")
                        import traceback
                        logger.error(traceback.format_exc())
                        logger.error(f"Full content.splitlines(): {split_lines}")
                        continue
                    if lower_line.startswith('to:'):
                        to_address = line[3:].strip()
                    elif lower_line.startswith('cc:'):
                        cc_addresses = line[3:].strip()
                    elif lower_line.startswith('subject:'):
                        subject = line[8:].strip()
            except Exception as e:
                logger.error(f"Exception in header extraction loop: {e}")
                import traceback
                logger.error(traceback.format_exc())
                logger.error(f"Full content.splitlines(): {split_lines}")

            # Check if message content should be stored (sender or IP whitelist)
            from email_server.models import get_sender_by_email, get_whitelisted_ip
            store_message = False
            sender_obj = get_sender_by_email(envelope.mail_from)
            if sender_obj and getattr(sender_obj, 'store_message_content', False):
                store_message = True
            elif client_ip:
                domain_name = sender_domain
                ip_obj = get_whitelisted_ip(client_ip, domain_name)
                if ip_obj and getattr(ip_obj, 'store_message_content', False):
                    store_message = True

            attachments_to_save = []
            # Get attachments path from settings
            attachments_path = settings['Attachments'].get('attachments_path', 'email_server/server_data/attachments')
            saved_attachments = []
            logger.debug(f"Using attachments base path: {attachments_path}")
            email_log_id = None

            if store_message:
                # Parse the message for attachments using the email library
                msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
                if msg.is_multipart():
                    # Get storage path for this sender
                    storage_path = self.get_attachment_storage_path(
                        attachments_base_path=attachments_path,
                        sender_domain=sender_domain,
                        username=username,
                        client_ip=client_ip
                    )
                    ensure_folder_exists(storage_path)
                    
                    for part in msg.walk():
                        content_disposition = part.get_content_disposition()
                        if content_disposition == 'attachment':
                            filename = part.get_filename()
                            if not filename:
                                continue
                                
                            # Get file data and validate
                            file_data = part.get_payload(decode=True)
                            if not file_data:
                                continue
                                
                            # Get proper content type
                            content_type = self.get_content_type(part, filename)
                            size = len(file_data)
                            
                            # Strip @domain from message_id for filename
                            clean_message_id = message_id.split('@')[0] if '@' in message_id else message_id
                            
                            # Build a unique file path
                            safe_filename = f"{clean_message_id}_{filename}"
                            file_path = os.path.join(storage_path, safe_filename)
                            
                            try:
                                # Ensure the directory exists before saving
                                ensure_folder_exists(file_path)
                                
                                # Save the file
                                with open(file_path, 'wb') as f:
                                    f.write(file_data)
                                logger.debug(f"Saved attachment {filename} ({content_type}) to {file_path}")
                                    
                                attachments_to_save.append({
                                    'filename': filename,
                                    'content_type': content_type,
                                    'file_path': file_path,
                                    'size': size
                                })
                            except Exception as e:
                                logger.error(f"Failed to save attachment {filename}: {str(e)}")
                                continue

            # Parse addresses to determine recipient types
            def parse_addresses(addr_str):
                if not isinstance(addr_str, str):
                    logger.warning(f"Expected string for address header, got {type(addr_str)}: {addr_str}")
                    return []
                
                return [addr.strip().lower() for addr in addr_str.split(',') if isinstance(addr, str) and addr.strip()]
            
            to_list = parse_addresses(to_address)
            cc_list = parse_addresses(cc_addresses)
            
            # Map recipients to their types based on headers
            recipient_type_map = {}
            for rcpt in envelope.rcpt_tos:
                if not isinstance(rcpt, str):
                    logger.warning(f"Expected string for recipient, got {type(rcpt)}: {rcpt}")
                    continue
                rcpt_l = rcpt.lower()
                if rcpt_l in to_list:
                    recipient_type_map[rcpt] = 'to'
                elif rcpt_l in cc_list:
                    recipient_type_map[rcpt] = 'cc'
                else:
                    recipient_type_map[rcpt] = 'bcc'  # Any recipient not in To/Cc is a Bcc

            # Build recipient results
            recipient_results = []
            recipient_types = []
            for rcpt in envelope.rcpt_tos:
                rtype = recipient_type_map[rcpt]
                recipient_results.append({'recipient': rcpt, 'recipient_type': rtype, 'status': 'pending'})
                recipient_types.append(rtype)

            # Relay the email and get per-recipient results
            relay_results = await self.email_relay.relay_email_async(
                envelope.mail_from,
                envelope.rcpt_tos,
                signed_content,
                username=username,
                cc_addresses=cc_addresses,
                bcc_addresses=None,  # BCC addresses are handled through envelope.rcpt_tos
                recipient_types=recipient_types
            )

            # Update status in recipient_results
            for result in relay_results:
                for r in recipient_results:
                    if r['recipient'] == result['recipient'] and r['recipient_type'] == result.get('recipient_type', 'to'):
                        r.update(result)
                        break

            # Determine overall status
            status = 'relayed' if all(r['status'] == 'success' for r in recipient_results) else 'failed'

            # Extract headers and parse message content
            msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
            
            # Extract headers
            email_headers = []
            for name, value in msg.items():
                email_headers.append(f"{name}: {value}")
            email_headers = '\n'.join(email_headers)

            # Extract only the text content, not attachments
            message_body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_maintype() == 'text' and part.get_content_disposition() is None:
                        # This is likely the main message text
                        charset = part.get_content_charset() or 'utf-8'
                        try:
                            part_content = part.get_payload(decode=True).decode(charset)
                            message_body += part_content + "\n"
                        except Exception as e:
                            logger.warning(f"Failed to decode message part: {e}")
            else:
                # Not multipart - if it's text, use it as is
                if msg.get_content_maintype() == 'text':
                    charset = msg.get_content_charset() or 'utf-8'
                    try:
                        message_body = msg.get_payload(decode=True).decode(charset)
                    except Exception as e:
                        logger.warning(f"Failed to decode message: {e}")

            # Trim any extra whitespace
            message_body = message_body.strip()

            # Get client IP without port
            client_ip = getattr(session, 'peer', ['unknown'])[0].split(':')[0] if hasattr(session, 'peer') else 'unknown'

            # Log the email with all details
            self.email_relay.log_email(
                message_id=message_id,
                peer=client_ip,
                mail_from=envelope.mail_from,
                to_address=to_address,
                cc_addresses=cc_addresses,
                bcc_addresses=', '.join([r['recipient'] for r in recipient_results if r['recipient_type'] == 'bcc']),
                subject=subject,
                email_headers=email_headers,
                message_body=message_body,
                status=status,
                dkim_signed=dkim_signed,
                username=username,
                recipient_results=recipient_results
            )

            # Save attachments to DB, linked to the correct EmailLog
            if attachments_to_save:
                db_session = Session()
                try:
                    email_log = db_session.query(EmailLog).filter_by(message_id=message_id).first()
                    if email_log:
                        for att in attachments_to_save:
                            attachment = EmailAttachment(
                                email_log_id=email_log.id,
                                filename=att['filename'],
                                content_type=att['content_type'],
                                file_path=att['file_path'],
                                size=att['size']
                            )
                            db_session.add(attachment)
                        db_session.commit()
                except Exception as e:
                    logger.error(f"Failed to save attachments to DB: {e}")
                    db_session.rollback()
                finally:
                    db_session.close()

            if status == 'relayed':
                logger.debug(f'Email {message_id} successfully relayed')
                return '250 Message accepted for delivery'
            else:
                logger.error(f'Email {message_id} failed to relay')
                return '550 Message relay failed'
        except Exception as e:
            import traceback
            logger.error(f'Error handling email: {e}')
            logger.error(f'Traceback: {traceback.format_exc()}')
            logger.error(f'Locals: {locals()}')
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

    def get_attachment_storage_path(self, attachments_base_path: str, sender_domain: str, username: str = None, client_ip: str = None) -> str:
        """Generate the storage path for attachments based on sender domain, authentication, and date.
        
        Args:
            attachments_base_path: Base path for attachments storage
            sender_domain: Domain of the sender
            username: Authenticated username (if any)
            client_ip: Client IP address (if IP-based authentication)
            
        Returns:
            str: Full path where attachments should be stored, format:
                base/domain/[username|ip]/YYYY-DD-MMM/
        """

        # Get current date in YYYY-DD-MMM format using consistent time function
        current_date = get_current_time().strftime('%Y-%d-%b')  # e.g., 2025-14-Jun
        
        # Sanitize domain name for folder name
        safe_domain = sender_domain.replace('/', '_').replace('\\', '_')
        domain_path = os.path.join(attachments_base_path, safe_domain)
        
        # Determine auth-based subfolder path
        if username:
            # Sanitize username for folder name
            safe_username = username.replace('/', '_').replace('\\', '_')
            auth_path = os.path.join(domain_path, safe_username)
        elif client_ip:
            # Sanitize IP for folder name
            safe_ip = client_ip.replace(':', '_')
            auth_path = os.path.join(domain_path, safe_ip)
        else:
            # Fallback to domain-only path
            auth_path = domain_path
        
        # Add date-based subfolder
        return os.path.join(auth_path, current_date)

    def get_content_type(self, part, filename):
        """Get the correct content type for a file, trying multiple methods."""
                
        # First try the part's content type
        content_type = part.get_content_type()
        
        # If it's octet-stream, try to guess from filename
        if content_type == 'application/octet-stream':
            guessed_type, _ = mimetypes.guess_type(filename)
            if guessed_type:
                content_type = guessed_type
            else:
                # Use specific types for common extensions
                ext = filename.lower().split('.')[-1] if '.' in filename else ''
                type_map = {
                    'txt': 'text/plain',
                    'csv': 'text/csv',
                    'jpg': 'image/jpeg',
                    'jpeg': 'image/jpeg',
                    'png': 'image/png',
                    'gif': 'image/gif',
                    'pdf': 'application/pdf',
                    'json': 'application/json',
                    'xml': 'application/xml',
                    'html': 'text/html',
                    'htm': 'text/html',
                }
                content_type = type_map.get(ext, 'application/octet-stream')
                
        return content_type

class TLSController(Controller):
    """
    Custom controller for direct TLS (SMTPS, port 465) support.
    """
    
    def __init__(self, handler, ssl_context, hostname='localhost', port=40465):
        logger.debug(f"TLSController __init__: ssl_context={ssl_context is not None}")
        self._ssl_context = ssl_context  # Use private attribute to avoid conflicts
        self.smtp_hostname = hostname  # Store for HELO identification
        super().__init__(handler, hostname='0.0.0.0', port=port)  # Bind to all interfaces
    
    def factory(self):
        logger.debug(f"TLSController factory: ssl_context={self._ssl_context is not None}")
        logger.debug(f"TLSController factory: ssl_context object={self._ssl_context}")
        logger.debug(f"TLSController factory: hostname={self.smtp_hostname}")
        # This is direct TLS (SMTPS, port 465 style)
        smtp_instance = CustomSMTP(
            self.handler,
            tls_context=self._ssl_context,
            require_starttls=False,  # Direct TLS: do not advertise or require STARTTLS
            auth_require_tls=True,   # If auth is used, require TLS
            authenticator=self.handler.combined_authenticator,
            decode_data=True,
            hostname=self.smtp_hostname  # Use proper hostname for HELO
        )
        logger.debug(f"TLSController CustomSMTP instance created with TLS: {hasattr(smtp_instance, 'tls_context')}")
        return smtp_instance

class PlainController(Controller):
    """Controller for plain SMTP with authentication and IP whitelist fallback."""
    
    def __init__(self, handler, hostname='localhost', port=4025):
        self.smtp_hostname = hostname  # Store for HELO identification
        super().__init__(handler, hostname='0.0.0.0', port=port)  # Bind to all interfaces
    
    def factory(self):
        # Pass authenticator and set auth_require_tls=False to enable AUTH on plain port
        return CustomSMTP(
            self.handler,
            authenticator=self.handler.combined_authenticator,
            auth_require_tls=False,  # Allow AUTH on plain port
            decode_data=True,
            hostname=self.smtp_hostname  # Use proper hostname for HELO
        )
