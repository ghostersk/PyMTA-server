"""
SMTP Server Web UI Package

This package provides a web interface for managing the SMTP server.
"""

# First import the blueprint definition
from .routes import email_bp

# Then import all route functions
from .dashboard import *
from .domains import *
from .senders import *
from .ip_whitelist import *
from .dkim import *
from .settings import *
from .logs import *
from .view_message import *
