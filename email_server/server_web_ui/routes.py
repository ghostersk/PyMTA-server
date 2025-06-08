"""
Main routes and blueprint definition for the SMTP server web UI.
"""
from flask import Blueprint, render_template
from email_server.tool_box import get_logger
from datetime import datetime


# Create the main email blueprint
email_bp = Blueprint('email', __name__, 
                    template_folder='templates',
                    static_folder='static',
                    url_prefix='/pymta-manager')


logger = get_logger()

# Error handlers
@email_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return render_template('error.html', 
                         error_code=404,
                         error_message='Page not found',
                         current_time=datetime.now()), 404

@email_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal error: {error}")
    return render_template('error.html',
                         error_code=500,
                         error_message='Internal server error',
                         current_time=datetime.now()), 500