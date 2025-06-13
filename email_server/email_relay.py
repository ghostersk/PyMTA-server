"""
Email relay functionality for the SMTP server.
"""

import asyncio
import dns.resolver
from email_server.models import Session, EmailLog, EmailRecipientLog
from email_server.settings_loader import load_settings
from email_server.tool_box import get_logger, get_current_time
import aiosmtplib

logger = get_logger()

settings = load_settings()
_relay_tls_timeout = settings['Server'].get('relay_timeout', 15)

class EmailRelay:
    """Handles relaying emails to recipient mail servers."""

    def __init__(self):

        self.timeout = _relay_tls_timeout  # Increased timeout for TLS negotiations
        # Get the configured hostname for HELO/EHLO identification
        self.hostname = settings['Server'].get('helo_hostname',
                                             settings['Server'].get('hostname', 'localhost'))
        logger.debug(f"EmailRelay initialized with hostname: {self.hostname}")

    def _modify_headers_for_recipients(self, content, to_addresses, cc_addresses=None):
        """Modify email headers to set To and Cc fields, removing Bcc."""
        lines = content.splitlines()
        new_headers = []
        body_start = 0
        for i, line in enumerate(lines):
            if line.strip() == '':
                body_start = i + 1
                break
            # Skip existing To, Cc, Bcc headers

            if not line.lower().startswith(('to:', 'cc:', 'bcc:')):
                new_headers.append(line)

        # Add new To and Cc headers
        if to_addresses:
            new_headers.append(f"To: {', '.join(to_addresses)}")
        if cc_addresses:
            new_headers.append(f"Cc: {', '.join(cc_addresses)}")

        # Reconstruct the message
        body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ''
        return '\r\n'.join(new_headers) + '\r\n\r\n' + body

    async def relay_email_async(
        self,
        mail_from: str,
        rcpt_tos: list[str],
        content: str,
        username: str = None,
        cc_addresses: list[str] = None,
        bcc_addresses: list[str] = None,
        recipient_types: list[str] = None
    ) -> list[dict]:
        """Relay email to recipients' mail servers asynchronously with encryption.

        Args:
            mail_from (str): Sender email address.
            rcpt_tos (list[str]): List of recipient email addresses.
            content (str): Raw email content.
            username (str, optional): Authenticated username.
            cc_addresses (list[str], optional): CC addresses.
            bcc_addresses (list[str], optional): BCC addresses.
            recipient_types (list[str], optional): Recipient types (to/cc/bcc).

        Returns:
            list[dict]: Per-recipient delivery results.
        """
        results = []
        recipient_type_map = {}
        if recipient_types and len(recipient_types) == len(rcpt_tos):
            for addr, rtype in zip(rcpt_tos, recipient_types):
                recipient_type_map[addr] = rtype
        else:
            for addr in rcpt_tos:
                recipient_type_map[addr] = 'to'

        domain_groups = {}
        for rcpt in rcpt_tos:
            domain = rcpt.split('@')[1].lower()
            rtype = recipient_type_map.get(rcpt, 'to')
            if domain not in domain_groups:
                domain_groups[domain] = {'to': [], 'cc': [], 'bcc': []}
            domain_groups[domain][rtype].append(rcpt)

        for domain, recipients in domain_groups.items():
            to_recipients = recipients['to']
            cc_recipients = recipients['cc']
            bcc_recipients = recipients['bcc']
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                mx_records = sorted(mx_records, key=lambda x: x.preference)
                mx_hosts = [mx.exchange.to_text().rstrip('.') for mx in mx_records]
                logger.debug(f'Found MX records for {domain}: {mx_hosts}')
            except Exception as e:
                logger.error(f'Failed to resolve MX for {domain}: {e}')
                for rcpt in to_recipients + cc_recipients + bcc_recipients:
                    results.append({
                        'recipient': rcpt,
                        'status': 'failed',
                        'error_code': 'MX',
                        'error_message': str(e),
                        'server_response': None,
                        'recipient_type': recipient_type_map.get(rcpt, 'to')
                    })
                continue

            # Relay to To and Cc recipients together
            if to_recipients or cc_recipients:
                modified_content = self._modify_headers_for_recipients(content, to_recipients, cc_recipients)
                delivered = False
                last_error = None
                for mx_host in mx_hosts:
                    try:
                        # Only use port 25 for MX delivery
                        port = 25
                        smtp = aiosmtplib.SMTP(hostname=mx_host, port=port, timeout=self.timeout, local_hostname=self.hostname)
                        await smtp.connect()
                        ext = getattr(smtp, 'extensions', None)
                        if ext is None:
                            ext = getattr(smtp, 'esmtp_extensions', None)
                        if ext is None:
                            logger.error(f"SMTP object has no 'extensions' or 'esmtp_extensions'. Available attributes: {dir(smtp)}")
                            ext = {}
                        if 'starttls' in ext:
                            logger.debug(f'STARTTLS supported by {mx_host}:{port}, upgrading to TLS')
                            await smtp.starttls()
                        else:
                            logger.warning(f'STARTTLS not supported by {mx_host}:{port}, sending in plain text!')
                        response = await smtp.sendmail(mail_from, to_recipients + cc_recipients, modified_content)
                        logger.debug(f'Successfully relayed email to {to_recipients + cc_recipients} via {mx_host}:{port}')
                        for rcpt in to_recipients + cc_recipients:
                            results.append({
                                'recipient': rcpt,
                                'status': 'success',
                                'error_code': None,
                                'error_message': None,
                                'server_response': str(response),
                                'recipient_type': recipient_type_map.get(rcpt, 'to')
                            })
                        await smtp.quit()
                        delivered = True
                        break
                    except Exception as e:
                        logger.error(f'Failed to relay email to {to_recipients + cc_recipients} via {mx_host}:{port}: {e}')
                        last_error = {
                            'status': 'failed',
                            'error_code': 'RELAY',
                            'error_message': str(e),
                            'server_response': None
                        }
                        continue
                if not delivered and last_error:
                    for rcpt in to_recipients + cc_recipients:
                        results.append({
                            'recipient': rcpt,
                            'status': last_error['status'],
                            'error_code': last_error['error_code'],
                            'error_message': last_error['error_message'],
                            'server_response': last_error['server_response'],
                            'recipient_type': recipient_type_map.get(rcpt, 'to')
                        })

            # Relay to Bcc recipients individually
            for bcc in bcc_recipients:
                modified_content = self._modify_headers_for_recipients(content, [bcc], None)
                delivered = False
                last_error = None
                for mx_host in mx_hosts:
                    try:
                        port = 25
                        smtp = aiosmtplib.SMTP(hostname=mx_host, port=port, timeout=self.timeout, local_hostname=self.hostname)
                        await smtp.connect()
                        ext = getattr(smtp, 'extensions', None)
                        if ext is None:
                            ext = getattr(smtp, 'esmtp_extensions', None)
                        if ext is None:
                            logger.error(f"SMTP object has no 'extensions' or 'esmtp_extensions'. Available attributes: {dir(smtp)}")
                            ext = {}
                        if 'starttls' in ext:
                            logger.debug(f'STARTTLS supported by {mx_host}:{port} for BCC, upgrading to TLS')
                            await smtp.starttls()
                        else:
                            logger.warning(f'STARTTLS not supported by {mx_host}:{port} for BCC, sending in plain text!')
                        response = await smtp.sendmail(mail_from, [bcc], modified_content)
                        logger.debug(f'Successfully relayed BCC email to {bcc} via {mx_host}:{port}')
                        results.append({
                            'recipient': bcc,
                            'status': 'success',
                            'error_code': None,
                            'error_message': None,
                            'server_response': str(response),
                            'recipient_type': 'bcc'
                        })
                        await smtp.quit()
                        delivered = True
                        break
                    except Exception as e:
                        logger.error(f'Failed to relay BCC email to {bcc} via {mx_host}:{port}: {e}')
                        last_error = {
                            'status': 'failed',
                            'error_code': 'RELAY',
                            'error_message': str(e),
                            'server_response': None,
                            'recipient_type': 'bcc'
                        }
                        continue
                if not delivered and last_error:
                    results.append({
                        'recipient': bcc,
                        **last_error
                    })
        return results

    def relay_email(self, *args, **kwargs):
        """Synchronous wrapper for relay_email_async for compatibility."""
        return asyncio.run(self.relay_email_async(*args, **kwargs))

    def log_email(self, message_id, peer, mail_from, to_address, cc_addresses, bcc_addresses, subject, email_headers, message_body, status, dkim_signed=False, username=None, recipient_results=None):
        """Log email activity to database, including per-recipient results."""
        session_db = Session()
        try:
            # Determine status: relayed, partial, failed
            delivered = [r for r in (recipient_results or []) if r['status'] == 'success']
            failed = [r for r in (recipient_results or []) if r['status'] != 'success']
            if delivered and failed:
                overall_status = 'partial'
            elif delivered:
                overall_status = 'relayed'
            else:
                overall_status = 'failed'
            
            email_log = EmailLog(
                message_id=message_id,
                timestamp=get_current_time(),
                peer_ip=peer,
                mail_from=mail_from,
                to_address=to_address or '',
                cc_addresses=cc_addresses or '',
                bcc_addresses=bcc_addresses or '',
                subject=subject,
                email_headers=email_headers,
                message_body=message_body,
                status=overall_status,
                dkim_signed=dkim_signed,
                username=username
            )
            session_db.add(email_log)
            session_db.flush()
            
            # Log per-recipient results
            if recipient_results:
                for r in recipient_results:
                    recipient_log = EmailRecipientLog(
                        email_log_id=email_log.id,
                        recipient=r['recipient'],
                        recipient_type=r.get('recipient_type', 'to'),
                        status=r['status'],
                        error_code=r.get('error_code'),
                        error_message=r.get('error_message'),
                        server_response=r.get('server_response')
                    )
                    session_db.add(recipient_log)
            session_db.commit()
            logger.debug(f'Logged email: {message_id}')
        except Exception as e:
            session_db.rollback()
            logger.error(f'Error logging email: {e}')
        finally:
            session_db.close()