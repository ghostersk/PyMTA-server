"""
Database utilities for the SMTP server.
"""

import sys
import subprocess
from urllib.parse import urlparse
from email_server.tool_box import get_logger

logger = get_logger()

# Database driver mappings
DB_DRIVERS = {
    'mysql': {
        'package': 'pymysql',
        'import_name': 'pymysql',
        'friendly_name': 'MySQL'
    },
    'postgresql': {
        'package': 'psycopg2-binary',
        'import_name': 'psycopg2',
        'friendly_name': 'PostgreSQL'
    },
    'mssql': {
        'package': 'pyodbc',
        'import_name': 'pyodbc',
        'friendly_name': 'MSSQL'
    }
}

def install_package(package_name: str) -> bool:
    """
    Install a Python package using pip.
    
    Args:
        package_name: Name of the package to install
        
    Returns:
        bool: True if installation was successful, False otherwise
    """
    try:
        logger.info(f"Installing {package_name}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install {package_name}: {e}")
        return False

def import_or_install_driver(db_type: str) -> bool:
    """
    Import database driver, installing it if necessary.
    
    Args:
        db_type: Type of database ('mysql', 'postgresql', 'mssql')
        
    Returns:
        bool: True if driver is available (installed or already present), False otherwise
    """
    if db_type not in DB_DRIVERS:
        return True  # SQLite or unsupported type
        
    driver_info = DB_DRIVERS[db_type]
    try:
        __import__(driver_info['import_name'])
        return True
    except ImportError:
        logger.warning(f"{driver_info['friendly_name']} driver not found. Attempting to install...")
        if install_package(driver_info['package']):
            try:
                __import__(driver_info['import_name'])
                logger.info(f"Successfully installed {driver_info['friendly_name']} driver")
                return True
            except ImportError:
                logger.error(f"Failed to import {driver_info['friendly_name']} driver after installation")
                return False
        return False

def test_database_connection(url: str) -> tuple[bool, str]:
    """
    Test if a database connection can be established.
    
    Args:
        url: Database connection URL
        
    Returns:
        tuple: (success: bool, message: str)
        
    Supported URL formats:
        - sqlite:///path/to/file.db
        - mysql://user:password@host:port/dbname
        - postgresql://user:password@host:port/dbname
        - mssql+pyodbc://user:password@host:port/dbname?driver=ODBC+Driver+17+for+SQL+Server
    """
    try:
        # Parse the database URL
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        
        # SQLite connection test
        if scheme == 'sqlite':
            import sqlite3
            conn = sqlite3.connect(url.replace('sqlite:///', ''))
            conn.close()
            return True, "Successfully connected to SQLite database"
            
        # Other database types
        db_type = scheme.split('+')[0]  # Handle mssql+pyodbc
        if db_type not in DB_DRIVERS and db_type != 'sqlite':
            return False, f"Unsupported database type: {scheme}"
            
        # Try to import/install the required driver
        if not import_or_install_driver(db_type):
            return False, f"Failed to install required driver for {DB_DRIVERS[db_type]['friendly_name']}"
            
        # MySQL connection test
        if db_type == 'mysql':
            import pymysql
            params = {
                'host': parsed.hostname,
                'port': parsed.port or 3306,
                'user': parsed.username,
                'password': parsed.password,
                'db': parsed.path.lstrip('/')
            }
            conn = pymysql.connect(**params)
            conn.close()
            return True, "Successfully connected to MySQL database"
            
        # PostgreSQL connection test
        elif db_type == 'postgresql':
            import psycopg2
            conn = psycopg2.connect(url)
            conn.close()
            return True, "Successfully connected to PostgreSQL database"
            
        # MSSQL connection test
        elif db_type == 'mssql':
            import pyodbc
            conn = pyodbc.connect(url.replace('mssql+pyodbc://', ''))
            conn.close()
            return True, "Successfully connected to MSSQL database"
            
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Database connection error: {error_msg}")
        return False, f"Connection error: {error_msg}"
        
    return False, "Unknown error occurred" 