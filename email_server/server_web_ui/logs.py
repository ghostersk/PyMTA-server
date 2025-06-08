"""
Logs blueprint for the SMTP server web UI.

This module provides email and authentication log viewing functionality.
"""

from flask import render_template, request, jsonify
from email_server.models import Session, EmailLog, AuthLog, Domain
from email_server.tool_box import get_logger
from sqlalchemy import desc
from datetime import datetime, timedelta
from .routes import email_bp

logger = get_logger()


@email_bp.route('/logs')
def logs():
    """Display email and authentication logs."""
    session = Session()
    try:
        # Get filter parameters
        filter_type = request.args.get('type', 'all')
        page = request.args.get('page', 1, type=int)
        per_page = 50
        
        if filter_type == 'emails':
            # Email logs only
            total_query = session.query(EmailLog)
            logs_query = session.query(EmailLog).order_by(EmailLog.created_at.desc())
        elif filter_type == 'auth':
            # Auth logs only
            total_query = session.query(AuthLog)
            logs_query = session.query(AuthLog).order_by(AuthLog.created_at.desc())
        else:
            # Combined view (default)
            email_logs = session.query(EmailLog).order_by(EmailLog.created_at.desc()).limit(per_page//2).all()
            auth_logs = session.query(AuthLog).order_by(AuthLog.created_at.desc()).limit(per_page//2).all()
            
            # Convert to unified format
            combined_logs = []
            for log in email_logs:
                combined_logs.append({
                    'type': 'email',
                    'timestamp': log.created_at,
                    'data': log
                })
            for log in auth_logs:
                combined_logs.append({
                    'type': 'auth',
                    'timestamp': log.created_at,
                    'data': log
                })
            
            # Sort by timestamp
            combined_logs.sort(key=lambda x: x['timestamp'], reverse=True)
            
            return render_template('logs.html', 
                                 logs=combined_logs[:per_page], 
                                 filter_type=filter_type,
                                 page=page,
                                 has_next=len(combined_logs) > per_page,
                                 has_prev=page > 1)
        
        # Pagination for single type logs
        offset = (page - 1) * per_page
        total = total_query.count()
        logs = logs_query.offset(offset).limit(per_page).all()
        
        has_next = offset + per_page < total
        has_prev = page > 1
        
        return render_template('logs.html', 
                             logs=logs, 
                             filter_type=filter_type,
                             page=page,
                             has_next=has_next,
                             has_prev=has_prev)
    finally:
        session.close()