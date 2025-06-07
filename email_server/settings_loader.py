"""
Settings loader for the SMTP server.
Automatically generates settings.ini with default values if not present.
"""

import configparser
from pathlib import Path

SETTINGS_PATH = Path(__file__).parent.parent / 'settings.ini'

# Default values for settings.ini
DEFAULTS = {
    'Server': {
        'SMTP_PORT': '4025',
        'SMTP_TLS_PORT': '40587',
        'HOSTNAME': 'mail.example.com',
        'helo_hostname': 'mail.example.com',
        'BIND_IP': '0.0.0.0',
    },
    'Database': {
        'DATABASE_URL': 'sqlite:///email_server/server_data/smtp_server.db',
    },
    'Logging': {
        'LOG_LEVEL': 'INFO',
        'hide_info_aiosmtpd': 'true',
    },
    'Relay': {
        'RELAY_TIMEOUT': '10',
    },
    'TLS': {
        'TLS_CERT_FILE': 'email_server/ssl_certs/server.crt',
        'TLS_KEY_FILE': 'email_server/ssl_certs/server.key',
    },
    'DKIM': {
        'DKIM_KEY_SIZE': '2048',
    },
}

def generate_settings_ini(settings_path: Path = SETTINGS_PATH) -> None:
    """Generate settings.ini with default values if it does not exist."""
    if settings_path.exists():
        return
    config_parser = configparser.ConfigParser()
    for section, values in DEFAULTS.items():
        config_parser[section] = values
    with open(settings_path, 'w') as f:
        config_parser.write(f)

def load_settings(settings_path: Path = SETTINGS_PATH) -> configparser.ConfigParser:
    """Load settings from settings.ini, generating it if needed."""
    generate_settings_ini(settings_path)
    config_parser = configparser.ConfigParser()
    config_parser.read(settings_path)
    return config_parser
