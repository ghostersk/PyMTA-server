"""
Utility functions for the email server.
"""

import os
import logging
from email_server.settings_loader import load_settings
from datetime import datetime
import pytz
import time
import random

settings = load_settings()
helo_hostname = settings['Server'].get('helo_hostname', settings['Server'].get('hostname', 'localhost'))

def ensure_folder_exists(filepath):
    """
    Ensure that the folder for the given filepath exists.
    """
    if filepath.startswith("sqlite:///"):
        filepath = filepath.replace("sqlite:///", "", 1)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)



def setup_logging():
    """
    Set up global logging configuration using settings.ini.
    Should be called once at program entry point.
    Optionally hides aiosmtpd 'mail.log' INFO logs when global logging is INFO based on settings.
    """
    log_level = getattr(logging, settings['Logging']['LOG_LEVEL'], logging.INFO)
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    if not logging.getLogger().hasHandlers():
        logging.basicConfig(level=log_level, format=log_format)
    else:
        logging.getLogger().setLevel(log_level)

    # Hide aiosmtpd INFO logs if configured `hide_info_aiosmtpd = true`
    hide_info_aiosmtpd = settings['Logging'].get('hide_info_aiosmtpd', 'true').lower() == 'true'
    if hide_info_aiosmtpd and log_level == logging.INFO:
        # Set aiosmtpd mail.log to WARNING level to hide INFO logs
        logging.getLogger('mail.log').setLevel(logging.WARNING)

def get_logger(name=None):
    """
    Get a logger with the given name (default: module name).
    Ensures logging is set up before returning the logger.
    """
    setup_logging()
    if name is None:
        # Get the caller's file name
        import inspect
        frame = inspect.currentframe()
        # Go back one frame to the caller
        caller_frame = frame.f_back
        filename = caller_frame.f_globals.get('__file__', None)
        if filename:
            base = os.path.basename(filename)
            name, ext = os.path.splitext(base)
            name = name if ext == '.py' else base
        else:
            name = '__main__'
    return logging.getLogger(name)

def get_current_time():
    """Get current time with timezone from settings."""
    timezone = pytz.timezone(settings['Server'].get('time_zone', 'UTC'))
    return datetime.now(timezone)

def generate_message_id(hostname=helo_hostname) -> str:
    """Generate a consistent Message-ID for both email headers and database storage.
    
    Returns:
        str: Message-ID in format YYYYMMDDhhmmss.RANDOM@hostname without brackets
    """
    timestamp = time.strftime('%Y%m%d%H%M%S')
    random_id = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    return f"{timestamp}.{random_id}@{hostname}"