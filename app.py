#!/usr/bin/env python3
"""
Unified SMTP Server with Web Management Frontend

This application runs both the SMTP server and the Flask web frontend
in a single integrated application.

Usage:
    python app.py                    # Run with default settings
    python app.py --smtp-only        # Run SMTP server only
    python app.py --web-only         # Run web frontend only
    python app.py --debug            # Enable debug mode
    python app.py --init-data        # Initialize sample data and exit
"""

import os
import sys
import asyncio
import threading
import signal
import argparse
from datetime import datetime
from zoneinfo import ZoneInfo
from flask import Flask, render_template, redirect, url_for, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import subprocess

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import SMTP server components
from email_server.server_runner import start_server
from email_server.models import create_tables, Session, Domain, Sender, WhitelistedIP, DKIMKey, hash_password
from email_server.settings_loader import load_settings
from email_server.tool_box import get_logger
from email_server.dkim_manager import DKIMManager

# Import Flask frontend
from email_server.server_web_ui.routes import email_bp

logger = get_logger()

class SMTPServerApp:
    """Unified SMTP Server and Web Frontend Application"""
    
    def __init__(self, config_file='settings.ini'):
        self.config_file = config_file
        self.settings = load_settings()
        self.flask_app = None
        self.smtp_task = None
        self.loop = None
        self.shutdown_requested = False
        self.shutdown_event = None
    
    def _get_absolute_database_url(self):
        """Convert relative database URL to absolute path for Flask-SQLAlchemy"""
        db_url = self.settings['Database']['database_url']
        
        # If it's already absolute or not a SQLite file path, return as-is
        if not db_url.startswith('sqlite:///') or db_url.startswith('sqlite:////'):
            return db_url
        
        # Convert relative SQLite path to absolute
        # Remove 'sqlite:///' prefix
        relative_path = db_url[10:]  # len('sqlite:///') = 10
        
        # Get absolute path relative to project root
        project_root = os.path.dirname(os.path.abspath(__file__))
        absolute_path = os.path.join(project_root, relative_path)
        
        return f'sqlite:///{absolute_path}'

    def create_flask_app(self):
        """Create and configure the Flask application"""
        app = Flask(__name__, 
                   static_folder='email_server/server_web_ui/static',
                   template_folder='email_server/server_web_ui/templates')
        
        # Flask configuration
        app.config.update({
            'SECRET_KEY': self.settings.get('Flask', 'secret_key', fallback='change-this-secret-key-in-production'),
            # Convert relative database path to absolute path
            'SQLALCHEMY_DATABASE_URI': self._get_absolute_database_url(),
            'SQLALCHEMY_TRACK_MODIFICATIONS': False,
            'TEMPLATES_AUTO_RELOAD': True,
            'SEND_FILE_MAX_AGE_DEFAULT': 0  # Disable caching for development
        })
        
        # Initialize database
        db = SQLAlchemy(app)
        
        # Import existing models and register them with Flask-SQLAlchemy
        from email_server.models import Base, Domain, Sender, WhitelistedIP, DKIMKey, EmailLog, AuthLog, CustomHeader
        # Set the metadata for Flask-Migrate to use existing models
        db.Model.metadata = Base.metadata
        
        migrate = Migrate(app, db, directory='migrations')
        
        # Create database tables if they don't exist
        with app.app_context():
            create_tables()
        
        # Register the email management blueprint
        app.register_blueprint(email_bp)
        
        # Main application routes
        @app.route('/')
        def index():
            """Redirect root to email dashboard"""
            return redirect(url_for('email.dashboard'))

        # Error handlers
        @app.errorhandler(404)
        def not_found_error(error):
            """Handle 404 errors"""
            return render_template('error.html', 
                                 error_code=404,
                                 error_message="Page not found",
                                 error_details="The requested page could not be found."), 404
        
        @app.errorhandler(500)
        def internal_error(error):
            """Handle 500 errors"""
            logger.error(f"Internal error: {error}")
            return render_template('error.html',
                                 error_code=500,
                                 error_message="Internal server error",
                                 error_details=str(error)), 500
        
        @app.route('/health')
        def health_check():
            """Health check endpoint"""
            return jsonify(self.check_health())
        
        # Context processors for templates
        @app.context_processor
        def utility_processor():
            """Add utility functions to template context"""
            return {
                'moment': datetime,
                'len': len,
                'enumerate': enumerate,
                'zip': zip,
                'str': str,
                'int': int,
                'check_health': self.check_health
            }
        
        self.flask_app = app
        return app
    
    def init_sample_data(self):
        """Initialize the database with sample data for testing"""
        try:
            # Initialize database
            create_tables()
            session = Session()
            
            try:
                # Add sample domains
                sample_domains = [
                    'example.com',
                ]
                
                for domain_name in sample_domains:
                    existing = session.query(Domain).filter_by(domain_name=domain_name).first()
                    if not existing:
                        domain = Domain(domain_name=domain_name)
                        session.add(domain)
                        logger.info(f"Added sample domain: {domain_name}")
                
                session.commit()
                
                # Generate DKIM keys for new domains
                dkim_manager = DKIMManager()
                for domain_name in sample_domains:
                    dkim_manager.generate_dkim_keypair(domain_name)
                
                # Add sample senders
                sample_senders = [
                    ('admin@example.com', 'example.com', 'admin123', False),
                ]
                
                for email, domain_name, password, can_send_as_domain in sample_senders:
                    existing = session.query(Sender).filter_by(email=email).first()
                    if not existing:
                        domain = session.query(Domain).filter_by(domain_name=domain_name).first()
                        if domain:
                            sender = Sender(
                                email=email,
                                password_hash=hash_password(password),
                                domain_id=domain.id,
                                can_send_as_domain=can_send_as_domain
                            )
                            session.add(sender)
                            logger.info(f"Added sample sender: {email}")
                
                # Add sample whitelisted IPs
                sample_ips = [
                    ('127.0.0.1', 'example.com'),
                ]
                
                for ip, domain_name in sample_ips:
                    domain = session.query(Domain).filter_by(domain_name=domain_name).first()
                    if domain:
                        existing = session.query(WhitelistedIP).filter_by(
                            ip_address=ip, domain_id=domain.id
                        ).first()
                        if not existing:
                            whitelist = WhitelistedIP(
                                ip_address=ip,
                                domain_id=domain.id
                            )
                            session.add(whitelist)
                            logger.info(f"Added sample whitelisted IP: {ip} for {domain_name}")
                
                session.commit()
                logger.info("Sample data initialized successfully!")
                
            finally:
                session.close()
                
        except Exception as e:
            logger.error(f"Error initializing sample data: {e}")
            raise
    
    async def start_smtp_server(self):
        """Start the SMTP server in async context"""
        try:
            logger.info("Starting SMTP server...")
            await start_server(self.shutdown_event)
        except Exception as e:
            logger.error(f"SMTP server error: {e}")
            if not self.shutdown_requested:
                raise
    
    def run_smtp_server(self):
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.shutdown_event = asyncio.Event()

            # Only register signal handlers if in the main thread
            if threading.current_thread() is threading.main_thread():
                for sig in (signal.SIGINT, signal.SIGTERM):
                    try:
                        self.loop.add_signal_handler(sig, self.shutdown_event.set)
                    except NotImplementedError:
                        pass  # Not available on Windows

            self.smtp_task = self.loop.create_task(self.start_smtp_server())
            self.loop.run_until_complete(self.smtp_task)
        except (asyncio.CancelledError, KeyboardInterrupt):
            logger.info("SMTP server task was cancelled or interrupted")
        except Exception as e:
            if not self.shutdown_requested:
                logger.error(f"SMTP server thread error: {e}")
        finally:
            if self.loop and self.loop.is_running():
                self.loop.stop()
            if self.loop:
                self.loop.close()
            if self.shutdown_requested:
                os._exit(0)
    
    def run(self, smtp_only=False, web_only=False, debug=False, host='127.0.0.1', port=5000):
        """Run the unified application"""
        # If running under Gunicorn, do not start Flask dev server
        if 'gunicorn' in os.environ.get('SERVER_SOFTWARE', '').lower():
            logger.info("Running under Gunicorn. Flask app will be served by Gunicorn WSGI server.")
            app = self.create_flask_app()
            return app
        
        if web_only:
            # Run only Flask web frontend
            logger.info("Starting web frontend only...")
            app = self.create_flask_app()
            try:
                logger.info(f"Web frontend starting at http://{host}:{port}")
                app.run(host=host, port=port, debug=debug, threaded=True, use_reloader=False)
            except KeyboardInterrupt:
                logger.info("Web server interrupted by user")
            return
        
        if smtp_only:
            # Run only SMTP server
            logger.info("Starting SMTP server only...")
            try:
                asyncio.run(self.start_smtp_server())
            except KeyboardInterrupt:
                logger.info("SMTP server interrupted by user")
            return
        
        # Run both SMTP server and web frontend
        logger.info("Starting unified SMTP server with web management frontend...")
        
        # Start SMTP server in a separate thread
        smtp_thread = threading.Thread(target=self.run_smtp_server, daemon=True)
        smtp_thread.start()
        
        # Give SMTP server time to start
        import time
        time.sleep(2)
        
        # Start Flask web frontend in main thread
        try:
            app = self.create_flask_app()
            logger.info(f"Web frontend starting at http://{host}:{port}")
            logger.info("SMTP server running in background")
            
            app.run(host=host, port=port, debug=debug, threaded=True, use_reloader=False)
                
        except KeyboardInterrupt:
            logger.info("Application interrupted by user")
        finally:
            self.shutdown_requested = True

    def check_health(self):
        """Check the health of all services"""
        status = {
            'status': 'healthy',
            'timestamp': datetime.now(ZoneInfo('Europe/London')).isoformat(),
            'services': {
                'smtp_server': 'running' if self.smtp_task and not self.smtp_task.done() else 'stopped',
                'web_frontend': 'running',
                'database': 'ok'
            },
            'version': '1.0.0'
        }
        
        # Check database connection
        try:
            session = Session()
            # Try to query a simple table to verify connection
            session.query(Domain).first()
            session.close()
        except Exception as e:
            status['services']['database'] = 'error'
            status['status'] = 'degraded'
            logger.error(f"Database health check failed: {e}")
            # Try to reconnect to database
            try:
                create_tables()
                logger.info("Database reconnection attempted")
            except Exception as reconnect_error:
                logger.error(f"Database reconnection failed: {reconnect_error}")
        
        # If any service is not running, set overall status to degraded
        if status['services']['smtp_server'] == 'stopped' or status['services']['database'] == 'error':
            status['status'] = 'degraded'
        
        return status


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Unified SMTP Server with Web Management')
    parser.add_argument('--smtp-only', action='store_true', help='Run SMTP server only')
    parser.add_argument('--web-only', action='store_true', help='Run web frontend only')
    parser.add_argument('--host', default='127.0.0.1', help='Web server host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000, help='Web server port (default: 5000)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--init-data', action='store_true', help='Initialize sample data and exit')
    parser.add_argument('--config', default='settings.ini', help='Configuration file path')
    
    args = parser.parse_args()
    
    # Create application instance
    try:
        app = SMTPServerApp(args.config)
        
        # Initialize sample data if requested
        if args.init_data:
            logger.info("Initializing sample data...")
            # app.init_sample_data() # For testing uncomment, adds sample domain
            logger.info("Sample data initialization complete")
            return
        
        # Print startup information
        settings = load_settings()
        smtp_port = settings.get('Server', 'SMTP_PORT', fallback='25')
        smtp_tls_port = settings.get('Server', 'SMTP_TLS_PORT', fallback='587')
        
        print(f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    SMTP Server with Web Management                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

Configuration:
  • Configuration file: {args.config}
  • SMTP Server ports: {smtp_port} (plain), {smtp_tls_port} (TLS)
  • Web Interface: http://{args.host}:{args.port}
  • Debug mode: {'ON' if args.debug else 'OFF'}

Services:
  • SMTP Server: {'Starting...' if not args.web_only else 'Disabled'}
  • Web Frontend: {'Starting...' if not args.smtp_only else 'Disabled'}

Available app web test routes:

  • /health               → Health check
  • /api/server/status    → Server status API

To initialize sample data:
  python app.py --init-data

Press Ctrl+C to stop the server
        """)
        
        # Run the application
        app.run(
            smtp_only=args.smtp_only,
            web_only=args.web_only,
            debug=args.debug,
            host=args.host,
            port=args.port
        )
        
    except KeyboardInterrupt:
        logger.info("Application shutdown requested")
    except Exception as e:
        logger.error(f"Application error: {e}")
        sys.exit(1)


# For Flask CLI: expose a create_app() factory at module level
flask_app = SMTPServerApp().create_flask_app()



if __name__ == '__main__':
    main()
