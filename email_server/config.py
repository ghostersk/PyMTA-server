"""
Configuration settings for the SMTP server.
"""

# Server settings
SMTP_PORT = 4025
SMTP_TLS_PORT = 40587
HOSTNAME = 'localhost'

# Database settings
DATABASE_URL = 'sqlite:///email_server/server_data/smtp_server.db'

# Logging settings
LOG_LEVEL = 'INFO'

# Email relay settings
RELAY_TIMEOUT = 10

# TLS settings
TLS_CERT_FILE = 'email_server/ssl_certs/server.crt'
TLS_KEY_FILE = 'email_server/ssl_certs/server.key'

# DKIM settings
DKIM_SELECTOR = 'default'
DKIM_KEY_SIZE = 2048
