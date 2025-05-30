"""
Email relay functionality for the SMTP server.
"""

import dns.resolver
import smtplib
import logging
from datetime import datetime
from models import Session, EmailLog

logger = logging.getLogger(__name__)

class EmailRelay:
    """Handles relaying emails to recipient mail servers."""
    
    def __init__(self):
        self.timeout = 10
    
    def relay_email(self, mail_from, rcpt_tos, content):
        """Relay email to recipient's mail server."""
        try:
            for rcpt in rcpt_tos:
                domain = rcpt.split('@')[1]
                try:
                    mx_records = dns.resolver.resolve(domain, 'MX')
                    mx_host = mx_records[0].exchange.to_text().rstrip('.')
                except Exception as e:
                    logger.error(f'Failed to resolve MX for {domain}: {e}')
                    return False

                try:
                    with smtplib.SMTP(mx_host, 25, timeout=self.timeout) as relay_server:
                        relay_server.set_debuglevel(1)
                        relay_server.sendmail(mail_from, rcpt, content)
                    logger.info(f'Relayed email to {rcpt} via {mx_host}')
                except Exception as e:
                    logger.error(f'Failed to relay email to {rcpt}: {e}')
                    return False
            return True
        except Exception as e:
            logger.error(f'General relay error: {e}')
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
