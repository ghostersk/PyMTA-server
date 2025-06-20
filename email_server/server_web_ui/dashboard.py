"""
Dashboard routes for the SMTP server web UI.

This module provides the main dashboard view and overview functionality.
"""

from flask import render_template
from email_server.models import Session, Domain, Sender, DKIMKey, EmailLog, AuthLog, EmailRecipientLog
from email_server.tool_box import get_logger
from .routes import email_bp

logger = get_logger()

# Dashboard and Main Routes
@email_bp.route('/')
def dashboard():
    """Main dashboard showing overview of the email server."""
    session = Session()
    try:
        # Get counts
        domain_count = session.query(Domain).filter_by(is_active=True).count()
        sender_count = session.query(Sender).filter_by(is_active=True).count()
        dkim_count = session.query(DKIMKey).filter_by(is_active=True).count()
        
        # Get recent email logs
        recent_emails = session.query(EmailLog).order_by(EmailLog.created_at.desc()).limit(10).all()
        # Get recipient logs for each recent email
        recipient_logs_map = {email.id: session.query(EmailRecipientLog).filter_by(email_log_id=email.id).all() for email in recent_emails}
        
        # Get recent auth logs
        recent_auths = session.query(AuthLog).order_by(AuthLog.created_at.desc()).limit(10).all()
        
        return render_template('dashboard.html',
                             domain_count=domain_count,
                             sender_count=sender_count,
                             dkim_count=dkim_count,
                             recent_emails=recent_emails,
                             recent_auths=recent_auths,
                             recipient_logs_map=recipient_logs_map)
    finally:
        session.close()