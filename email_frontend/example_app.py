#!/usr/bin/env python3
"""
Example Flask Application demonstrating SMTP Management Frontend
This example shows how to integrate the email_frontend Blueprint
"""

import os
import sys
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the SMTP server models and utilities
try:
    from database import Database, Domain, User, WhitelistedIP, DKIMKey, EmailLog, AuthLog
    from email_frontend.blueprint import email_bp
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure you're running this from the SMTP_Server directory")
    sys.exit(1)

def create_app(config_file='settings.ini'):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Basic Flask configuration
    app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///smtp_server.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize database
    db = SQLAlchemy(app)
    
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
    
    # Register the email management blueprint
    app.register_blueprint(email_bp, url_prefix='/email')
    
    # Main application routes
    @app.route('/')
    def index():
        """Main application dashboard."""
        return redirect(url_for('email.dashboard'))
    
    @app.route('/health')
    def health_check():
        """Simple health check endpoint."""
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'SMTP Management Frontend'
        })
    
    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        """Handle 404 errors."""
        return render_template('error.html', 
                             error_code=404,
                             error_message="Page not found",
                             error_details="The requested page could not be found."), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 errors."""
        return render_template('error.html',
                             error_code=500,
                             error_message="Internal server error",
                             error_details=str(error)), 500
    
    @app.errorhandler(403)
    def forbidden_error(error):
        """Handle 403 errors."""
        return render_template('error.html',
                             error_code=403,
                             error_message="Access forbidden",
                             error_details="You don't have permission to access this resource."), 403
    
    # Context processors for templates
    @app.context_processor
    def utility_processor():
        """Add utility functions to template context."""
        return {
            'moment': datetime,
            'len': len,
            'enumerate': enumerate,
            'zip': zip,
            'str': str,
            'int': int,
        }
    
    return app

def init_sample_data():
    """Initialize the database with sample data for testing."""
    try:
        # Initialize database connection
        db = Database('settings.ini')
        
        # Add sample domains
        sample_domains = [
            'example.com',
            'testdomain.org',
            'mydomain.net'
        ]
        
        for domain_name in sample_domains:
            if not db.get_domain(domain_name):
                domain = Domain(domain_name)
                db.add_domain(domain)
                print(f"Added sample domain: {domain_name}")
        
        # Add sample users
        sample_users = [
            ('admin@example.com', 'example.com', 'admin123'),
            ('user@example.com', 'example.com', 'user123'),
            ('test@testdomain.org', 'testdomain.org', 'test123')
        ]
        
        for email, domain, password in sample_users:
            if not db.get_user(email):
                user = User(email, domain, password)
                db.add_user(user)
                print(f"Added sample user: {email}")
        
        # Add sample whitelisted IPs
        sample_ips = [
            ('127.0.0.1', 'example.com', 'localhost'),
            ('192.168.1.0/24', 'example.com', 'local network'),
            ('10.0.0.0/8', 'testdomain.org', 'private network')
        ]
        
        for ip, domain, description in sample_ips:
            if not db.get_whitelisted_ip(ip, domain):
                whitelisted_ip = WhitelistedIP(ip, domain, description)
                db.add_whitelisted_ip(whitelisted_ip)
                print(f"Added sample whitelisted IP: {ip} for {domain}")
        
        print("Sample data initialized successfully!")
        
    except Exception as e:
        print(f"Error initializing sample data: {e}")

def main():
    """Main function to run the example application."""
    import argparse
    
    parser = argparse.ArgumentParser(description='SMTP Management Frontend Example')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--init-data', action='store_true', help='Initialize sample data')
    parser.add_argument('--config', default='settings.ini', help='Configuration file path')
    
    args = parser.parse_args()
    
    # Initialize sample data if requested
    if args.init_data:
        print("Initializing sample data...")
        init_sample_data()
        return
    
    # Create Flask application
    app = create_app(args.config)
    
    print(f"""
    SMTP Management Frontend Example
    ================================
    
    Starting server on http://{args.host}:{args.port}
    
    Available routes:
    - /                     -> Dashboard (redirects to /email/dashboard)
    - /email/dashboard      -> Main dashboard
    - /email/domains        -> Domain management
    - /email/users          -> User management  
    - /email/ips            -> IP whitelist management
    - /email/dkim           -> DKIM management
    - /email/settings       -> Server settings
    - /email/logs           -> Email and authentication logs
    - /health               -> Health check endpoint
    
    Debug mode: {'ON' if args.debug else 'OFF'}
    
    To initialize sample data, run:
    python example_app.py --init-data
    """)
    
    # Run the Flask application
    try:
        app.run(
            host=args.host,
            port=args.port,
            debug=args.debug,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
