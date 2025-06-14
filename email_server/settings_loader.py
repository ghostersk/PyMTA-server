"""
Settings loader for the SMTP server.
Automatically generates settings.ini with default values if not present.
"""

import configparser
from pathlib import Path

SETTINGS_PATH = Path(__file__).parent.parent / 'settings.ini'

# Default values and comments for settings.ini
DEFAULTS = {
    'Server': {
        '; Server configuration for SMTP ports and hostname': None,
        '; Plain SMTP port for internal/whitelisted IPs': None,
        'SMTP_PORT': '4025',
        '; TLS SMTP port for authenticated users': None,
        'SMTP_TLS_PORT': '40465',
        '; Server hostname for HELO/EHLO identification': None,
        'HOSTNAME': 'mail.example.com',
        '; Override HELO hostname': None,
        'helo_hostname': 'mail.example.com',
        '; IP address to bind to (0.0.0.0 = all interfaces), on Windows must use specific IP': None,
        'BIND_IP': '0.0.0.0',
        '; Custom server banner (to make it empty use "" must be double quotes)': None,
        'server_banner': "",
        '; Time zone for the server': None,
        'TIME_ZONE': 'Europe/London',
    },
    'Database': {
        '; Database configuration': None,
        'DATABASE_URL': 'sqlite:///email_server/server_data/smtp_server.db',
    },
    'Logging': {
        '; Logging configuration': None,
        '; Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL': None,
        'LOG_LEVEL': 'INFO',
        '; Hide verbose aiosmtpd INFO messages when LOG_LEVEL = INFO': None,
        'hide_info_aiosmtpd': 'true',
    },
    'Relay': {
        '; Timeout in seconds for external SMTP connections': None,
        'RELAY_TIMEOUT': '30',
    },
    'TLS': {
        '; TLS/SSL certificate configuration': None,
        'TLS_CERT_FILE': 'email_server/ssl_certs/server.crt',
        'TLS_KEY_FILE': 'email_server/ssl_certs/server.key',
    },
    'DKIM': {
        '; DKIM signing configuration': None,
        '; RSA key size for DKIM keys (1024, 2048, 4096)': None,
        'DKIM_KEY_SIZE': '2048',
        '; Provide Public IP address of server, used for SPF in case detection fails': None,
        'SPF_SERVER_IP': '192.168.1.1',
    },
}

def generate_settings_ini(settings_path: Path = SETTINGS_PATH) -> None:
    """Generate settings.ini with default values and comments if it does not exist."""
    if settings_path.exists():
        return
    config_parser = configparser.ConfigParser(allow_no_value=True)
    for section, values in DEFAULTS.items():
        config_parser.add_section(section)
        for key, value in values.items():
            if key.startswith(';'):
                # This is a comment line
                config_parser.set(section, key)
            else:
                # This is a setting with value
                config_parser.set(section, key, value)
    with open(settings_path, 'w') as f:
        config_parser.write(f)

def load_settings(settings_path: Path = SETTINGS_PATH) -> configparser.ConfigParser:
    """Load settings from settings.ini, generating it if needed."""
    generate_settings_ini(settings_path)
    config_parser = configparser.ConfigParser()
    config_parser.read(settings_path)
    return config_parser
