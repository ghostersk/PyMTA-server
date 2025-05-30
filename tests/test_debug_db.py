"""
Debug script to test database operations.
"""

import sys
import os
import sqlite3

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("Testing database operations...")

# Test direct SQLite connection
try:
    conn = sqlite3.connect('smtp_server.db')
    cursor = conn.cursor()
    
    # Check tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    print(f"Tables in database: {[table[0] for table in tables]}")
    
    # Check domains
    cursor.execute("SELECT * FROM domains;")
    domains = cursor.fetchall()
    print(f"Domains: {domains}")
    
    conn.close()
    print("Direct SQLite test successful")
    
except Exception as e:
    print(f"Direct SQLite test failed: {e}")

# Test SQLAlchemy models
try:
    from models import Session, Domain, User, WhitelistedIP, create_tables
    print("Models imported successfully")
    
    # Create session
    session = Session()
    
    # Check domains
    domains = session.query(Domain).all()
    print(f"SQLAlchemy domains: {[(d.id, d.domain_name) for d in domains]}")
    
    session.close()
    print("SQLAlchemy test successful")
    
except Exception as e:
    print(f"SQLAlchemy test failed: {e}")
    import traceback
    traceback.print_exc()
