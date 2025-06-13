"""
Main routes and blueprint definition for the SMTP server web UI.
"""
from flask import Blueprint, render_template, request, jsonify, current_app
from email_server.models import Session, EmailLog, AuthLog
from email_server.tool_box import get_logger, get_current_time
from email_server.settings_loader import load_settings
from datetime import datetime
import pytz


# Create the main email blueprint
email_bp = Blueprint('email', __name__, 
                    template_folder='templates',
                    static_folder='static',
                    url_prefix='/pymta-manager')


logger = get_logger()

# Get timezone from settings
settings = load_settings()
timezone = pytz.timezone(settings['Server'].get('time_zone', 'UTC'))

@email_bp.app_template_filter('format_datetime')
def format_datetime(value, timezone=None):
    """Format datetime with the correct timezone from settings or argument."""
    if value is None:
        return ''
    import pytz
    if timezone is None:
        settings = load_settings()
        timezone = settings['Server'].get('time_zone', 'UTC')
    tz = pytz.timezone(timezone)
    if value.tzinfo is None:
        value = pytz.UTC.localize(value)
    local_dt = value.astimezone(tz)
    return local_dt.strftime('%Y-%m-%d %H:%M:%S')

from .view_message import *  # Import view_message routes

# Error handlers
@email_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return render_template('error.html', 
                         error_code=404,
                         error_message="Page not found",
                         current_time=get_current_time()), 404

@email_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal error: {error}")
    return render_template('error.html',
                         error_code=500,
                         error_message=str(error),
                         current_time=get_current_time()), 500