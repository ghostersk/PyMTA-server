"""
Settings blueprint for the SMTP server web UI.

This module provides server settings management functionality including:
- Settings viewing
- Settings updating
- Certificate management
- Database testing
- Public IP retrieval
"""

import os
import time
from pathlib import Path
import zoneinfo
from flask import render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from email_server.settings_loader import load_settings, SETTINGS_PATH
from email_server.tool_box import get_logger
from .utils import get_public_ip
from .database import test_database_connection
from .routes import email_bp

logger = get_logger()

# Certificate upload configuration
CERT_UPLOAD_FOLDER = Path(__file__).parent.parent / 'ssl_certs'
ALLOWED_EXTENSIONS = {'crt', 'key', 'pem'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_template_context():
    """Get template context with CSRF token and common data."""
    context = {
        'settings': load_settings(),
        'timezones': get_available_timezones(),
    }
    # Only add CSRF token if it exists and is enabled
    if hasattr(request, 'csrf_token'):
        context['csrf_token_value'] = request.csrf_token
    return context

@email_bp.route('/settings')
def settings():
    """Display and edit server settings."""
    return render_template('settings.html', **get_template_context())

@email_bp.route('/settings_update', methods=['POST'])
def settings_update():
    """Update server settings."""
    try:
        # Check if settings file exists and is writable
        if not os.path.exists(SETTINGS_PATH):
            logger.error(f"Settings file does not exist: {SETTINGS_PATH}")
            flash('Settings file does not exist.', 'error')
            return redirect(url_for('email.settings'))
            
        if not os.access(SETTINGS_PATH, os.W_OK):
            logger.error(f"Settings file is not writable: {SETTINGS_PATH}")
            flash('Settings file is not writable.', 'error')
            return redirect(url_for('email.settings'))
            
        # Load current settings
        config = load_settings()
        logger.info("Current settings loaded successfully")
        
        # Create case-insensitive form data mapping
        form_data = {}
        for key, value in request.form.items():
            form_data[key.lower()] = value
        logger.info(f"Received form data: {dict(request.form)}")
        
        # Update settings from form
        changes_made = False
        for section_name in config.sections():
            logger.debug(f"Processing section: {section_name}")
            for key in config[section_name]:
                if key.startswith(';'):  # Skip comment lines
                    continue
                    
                # Create case-insensitive form key
                form_key = f"{section_name}.{key}".lower()
                if form_key not in form_data:
                    logger.debug(f"Form key not found: {form_key}")
                    continue
                    
                old_value = config.get(section_name, key, fallback='').strip()
                new_value = form_data[form_key].strip()
                
                # Handle empty server banner special case
                if section_name == 'Server' and key == 'server_banner' and not new_value:
                    new_value = '""'
                
                # Log values for debugging
                logger.debug(f"Comparing {form_key}: old='{old_value}' new='{new_value}'")
                
                if old_value != new_value:
                    logger.info(f"Updating {form_key}: '{old_value}' -> '{new_value}'")
                    config.set(section_name, key, new_value)
                    changes_made = True
        
        if not changes_made:
            logger.warning("No changes detected in settings")
            flash('No changes were made to settings.', 'info')
            return redirect(url_for('email.settings'))
            
        # Save settings
        logger.info(f"Saving settings to: {SETTINGS_PATH}")
        try:
            with open(SETTINGS_PATH, 'w') as f:
                config.write(f)
            logger.info("Settings saved successfully")
            flash('Settings updated successfully. Restart the server to apply changes.', 'success')
        except IOError as e:
            logger.error(f"Failed to write settings file: {e}", exc_info=True)
            flash(f'Failed to save settings: {str(e)}', 'error')
        
        return redirect(url_for('email.settings'))
        
    except Exception as e:
        logger.error(f"Error updating settings: {e}", exc_info=True)
        flash(f'Error updating settings: {str(e)}', 'error')
        return redirect(url_for('email.settings'))

@email_bp.route('/api/settings/test_database', methods=['POST'])
def test_database_connection_endpoint():
    """Test database connection endpoint."""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'status': 'error', 'message': 'No database URL provided'})
        
        success, message = test_database_connection(data['url'])
        if success:
            return jsonify({'status': 'success', 'message': message})
        return jsonify({'status': 'error', 'message': message})
    
    except Exception as e:
        logger.error(f"Error testing database connection: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@email_bp.route('/api/settings/upload_cert', methods=['POST'])
def upload_cert():
    """Handle certificate file upload."""
    try:
        if 'cert_file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No file provided'})
        
        file = request.files['cert_file']
        if file.filename == '':
            return jsonify({'status': 'error', 'message': 'No file selected'})
        
        if file and allowed_file(file.filename):
            timestamp = int(time.time())
            filename = f'server{timestamp}.crt'
            filepath = CERT_UPLOAD_FOLDER / filename
            file.save(str(filepath))
            return jsonify({
                'status': 'success',
                'filepath': f'email_server/ssl_certs/{filename}'
            })
        
        return jsonify({'status': 'error', 'message': 'Invalid file type'})
    
    except Exception as e:
        logger.error(f"Error uploading certificate: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@email_bp.route('/api/settings/upload_key', methods=['POST'])
def upload_key():
    """Handle key file upload."""
    try:
        if 'key_file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No file provided'})
        
        file = request.files['key_file']
        if file.filename == '':
            return jsonify({'status': 'error', 'message': 'No file selected'})
        
        if file and allowed_file(file.filename):
            timestamp = int(time.time())
            filename = f'server{timestamp}.key'
            filepath = CERT_UPLOAD_FOLDER / filename
            file.save(str(filepath))
            return jsonify({
                'status': 'success',
                'filepath': f'email_server/ssl_certs/{filename}'
            })
        
        return jsonify({'status': 'error', 'message': 'Invalid file type'})
    
    except Exception as e:
        logger.error(f"Error uploading key file: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@email_bp.route('/api/settings/get_public_ip', methods=['GET'])
def get_server_ip():
    """Get server's public IP address."""
    try:
        ip = get_public_ip()
        if ip:
            return jsonify({'status': 'success', 'ip': ip})
        return jsonify({'status': 'error', 'message': 'Failed to get public IP'})
    
    except Exception as e:
        logger.error(f"Error getting public IP: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@email_bp.route('/test_attachments_path', methods=['POST'])
def test_attachments_path():
    """Test if the attachments path is writable."""
    path = request.form.get('path')
    if not path:
        return jsonify({'success': False, 'message': 'No path provided'})
        
    # Convert to absolute path if relative
    if not os.path.isabs(path):
        path = os.path.abspath(os.path.join(os.path.dirname(SETTINGS_PATH), path))
    
    try:
        # Create path if it doesn't exist
        os.makedirs(path, exist_ok=True)
        
        # Try to create a test file
        test_file = os.path.join(path, '.write_test')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        return jsonify({
            'success': True, 
            'message': 'Attachments path is valid and writable',
            'absolute_path': path
        })
    except Exception as e:
        logger.error(f"Error testing attachments path: {e}")
        return jsonify({
            'success': False, 
            'message': f'Error: {str(e)}',
            'absolute_path': path
        })

def get_available_timezones():
    """Get a list of all available timezones sorted alphabetically."""
    return sorted(zoneinfo.available_timezones())
