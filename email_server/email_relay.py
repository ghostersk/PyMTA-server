"""
Email relay functionality for the SMTP server.
"""

import dns.resolver
import smtplib
import ssl
from datetime import datetime
from email_server.models import Session, EmailLog
from email_server.tool_box import get_logger

logger = get_logger()

class EmailRelay:
    """Handles relaying emails to recipient mail servers."""
    
    def __init__(self):
        self.timeout = 30  # Increased timeout for TLS negotiations
    
    def relay_email(self, mail_from, rcpt_tos, content):
        """Relay email to recipient's mail server with opportunistic TLS."""
        try:
            for rcpt in rcpt_tos:
                domain = rcpt.split('@')[1]
                
                # Resolve MX record for the domain
                try:
                    mx_records = dns.resolver.resolve(domain, 'MX')
                    # Sort by priority (lower number = higher priority)
                    mx_records = sorted(mx_records, key=lambda x: x.preference)
                    mx_host = mx_records[0].exchange.to_text().rstrip('.')
                    logger.debug(f'Found MX record for {domain}: {mx_host}')
                except Exception as e:
                    logger.error(f'Failed to resolve MX for {domain}: {e}')
                    return False

                # Try to relay with opportunistic TLS
                if not self._relay_with_opportunistic_tls(mail_from, rcpt, content, mx_host):
                    return False
                    
            return True
        except Exception as e:
            logger.error(f'General relay error: {e}')
            return False
    
    def _relay_with_opportunistic_tls(self, mail_from, rcpt, content, mx_host):
        """Relay email with opportunistic TLS (like Gmail does)."""
        try:
            # First, try with STARTTLS (encrypted)
            try:
                with smtplib.SMTP(mx_host, 25, timeout=self.timeout) as relay_server:
                    relay_server.set_debuglevel(1)
                    
                    # Try to enable TLS if the server supports it
                    try:
                        # Check if server supports STARTTLS
                        relay_server.ehlo()
                        if relay_server.has_extn('starttls'):
                            logger.debug(f'Starting TLS connection to {mx_host}')
                            context = ssl.create_default_context()
                            # Allow self-signed certificates for mail servers
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                            relay_server.starttls(context=context)
                            relay_server.ehlo()  # Say hello again after STARTTLS
                            logger.debug(f'TLS connection established to {mx_host}')
                        else:
                            logger.warning(f'Server {mx_host} does not support STARTTLS, using plain text')
                    except Exception as tls_e:
                        logger.warning(f'STARTTLS failed with {mx_host}, continuing with plain text: {tls_e}')
                    
                    # Send the email
                    relay_server.sendmail(mail_from, rcpt, content)
                    logger.debug(f'Successfully relayed email to {rcpt} via {mx_host}')
                    return True
                    
            except Exception as e:
                logger.error(f'Failed to relay email to {rcpt} via {mx_host}: {e}')
                
                # Fallback: try alternative MX records if available
                try:
                    domain = rcpt.split('@')[1]
                    mx_records = dns.resolver.resolve(domain, 'MX')
                    mx_records = sorted(mx_records, key=lambda x: x.preference)
                    
                    # Try other MX records
                    for mx_record in mx_records[1:3]:  # Try up to 2 backup MX records
                        backup_mx = mx_record.exchange.to_text().rstrip('.')
                        logger.debug(f'Trying backup MX record: {backup_mx}')
                        
                        try:
                            with smtplib.SMTP(backup_mx, 25, timeout=self.timeout) as backup_server:
                                backup_server.set_debuglevel(1)
                                
                                # Try TLS with backup server too
                                try:
                                    backup_server.ehlo()
                                    if backup_server.has_extn('starttls'):
                                        context = ssl.create_default_context()
                                        context.check_hostname = False
                                        context.verify_mode = ssl.CERT_NONE
                                        backup_server.starttls(context=context)
                                        backup_server.ehlo()
                                        logger.debug(f'TLS connection established to backup {backup_mx}')
                                except Exception:
                                    logger.warning(f'STARTTLS failed with backup {backup_mx}, using plain text')
                                
                                backup_server.sendmail(mail_from, rcpt, content)
                                logger.debug(f'Successfully relayed email to {rcpt} via backup {backup_mx}')
                                return True
                        except Exception as backup_e:
                            logger.warning(f'Backup MX {backup_mx} also failed: {backup_e}')
                            continue
                            
                except Exception as fallback_e:
                    logger.error(f'All MX records failed for {rcpt}: {fallback_e}')
                
                return False
                
        except Exception as e:
            logger.error(f'Unexpected error in TLS relay: {e}')
            return False
    
    def log_email(self, message_id, peer, mail_from, rcpt_tos, content, status, dkim_signed=False):
        """Log email activity to database."""
        session_db = Session()
        try:
            # Convert content to string if it's bytes
            if isinstance(content, bytes):
                content_str = content.decode('utf-8', errors='replace')
            else:
                content_str = content
            
            email_log = EmailLog(
                message_id=message_id,
                timestamp=datetime.now(),
                peer=str(peer),
                mail_from=mail_from,
                rcpt_tos=', '.join(rcpt_tos),
                content=content_str,
                status=status,
                dkim_signed=dkim_signed
            )
            session_db.add(email_log)
            session_db.commit()
            logger.debug(f'Logged email: {message_id}')
        except Exception as e:
            session_db.rollback()
            logger.error(f'Error logging email: {e}')
        finally:
            session_db.close()