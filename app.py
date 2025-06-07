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
from flask import Flask, render_template, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import SMTP server components
from email_server.server_runner import start_server
from email_server.models import create_tables, Session, Domain, User, WhitelistedIP, DKIMKey, hash_password
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
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"Received signal {signum}, initiating shutdown...")
        self.shutdown_requested = True
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self._stop_smtp_server)
    
    def _stop_smtp_server(self):
        """Stop the SMTP server"""
        if self.smtp_task and not self.smtp_task.done():
            self.smtp_task.cancel()
            logger.info("SMTP server stopped")
    
    def create_flask_app(self):
        """Create and configure the Flask application"""
        app = Flask(__name__, 
                   static_folder='email_server/server_web_ui/static',
                   template_folder='email_server/server_web_ui/templates')
        
        # Flask configuration
        app.config.update({
            'SECRET_KEY': self.settings.get('Flask', 'secret_key', fallback='change-this-secret-key-in-production'),
            'SQLALCHEMY_DATABASE_URI': f"sqlite:///{self.settings.get('Database', 'database_path', fallback='email_server/server_data/smtp_server.db')}",
            'SQLALCHEMY_TRACK_MODIFICATIONS': False,
            'TEMPLATES_AUTO_RELOAD': True,
            'SEND_FILE_MAX_AGE_DEFAULT': 0  # Disable caching for development
        })
        
        # Initialize database
        db = SQLAlchemy(app)
        
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
        
        @app.route('/health')
        def health_check():
            """Health check endpoint"""
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'services': {
                    'smtp_server': 'running' if self.smtp_task and not self.smtp_task.done() else 'stopped',
                    'web_frontend': 'running'
                },
                'version': '1.0.0'
            })
        
        @app.route('/api/server/status')
        def server_status():
            """Get detailed server status"""
            session = Session()
            try:
                status = {
                    'smtp_server': {
                        'running': self.smtp_task and not self.smtp_task.done(),
                        'port': int(self.settings.get('Server', 'SMTP_PORT', fallback=25)),
                        'tls_port': int(self.settings.get('Server', 'SMTP_TLS_PORT', fallback=587)),
                        'hostname': self.settings.get('Server', 'hostname', fallback='localhost')
                    },
                    'database': {
                        'domains': session.query(Domain).filter_by(is_active=True).count(),
                        'users': session.query(User).filter_by(is_active=True).count(),
                        'dkim_keys': session.query(DKIMKey).filter_by(is_active=True).count(),
                        'whitelisted_ips': session.query(WhitelistedIP).filter_by(is_active=True).count()
                    },
                    'settings': {
                        'relay_enabled': self.settings.getboolean('Relay', 'enable_relay', fallback=False),
                        'tls_enabled': self.settings.getboolean('TLS', 'enable_tls', fallback=True),
                        'dkim_enabled': self.settings.getboolean('DKIM', 'enable_dkim', fallback=True)
                    }
                }
                return jsonify(status)
            finally:
                session.close()
        
        @app.route('/api/server/restart', methods=['POST'])
        def restart_server():
            """Restart the SMTP server (API endpoint)"""
            try:
                if self.smtp_task and not self.smtp_task.done():
                    self._stop_smtp_server()
                
                # Start SMTP server in a new task
                if self.loop:
                    self.smtp_task = asyncio.create_task(start_server())
                    return jsonify({'status': 'success', 'message': 'SMTP server restarted'})
                else:
                    return jsonify({'status': 'error', 'message': 'Event loop not available'}), 500
            except Exception as e:
                logger.error(f"Error restarting server: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
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
                    'testdomain.org',
                    'mydomain.net'
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
                
                # Add sample users
                sample_users = [
                    ('admin@example.com', 'example.com', 'admin123', True),
                    ('user@example.com', 'example.com', 'user123', False),
                    ('test@testdomain.org', 'testdomain.org', 'test123', False)
                ]
                
                for email, domain_name, password, can_send_as_domain in sample_users:
                    existing = session.query(User).filter_by(email=email).first()
                    if not existing:
                        domain = session.query(Domain).filter_by(domain_name=domain_name).first()
                        if domain:
                            user = User(
                                email=email,
                                password_hash=hash_password(password),
                                domain_id=domain.id,
                                can_send_as_domain=can_send_as_domain
                            )
                            session.add(user)
                            logger.info(f"Added sample user: {email}")
                
                # Add sample whitelisted IPs
                sample_ips = [
                    ('127.0.0.1', 'example.com'),
                    ('192.168.1.0/24', 'example.com'),
                    ('10.0.0.0/8', 'testdomain.org')
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
            await start_server()
        except Exception as e:
            logger.error(f"SMTP server error: {e}")
            if not self.shutdown_requested:
                raise
    
    def run_smtp_server(self):
        """Run SMTP server in a separate thread"""
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            
            self.smtp_task = self.loop.create_task(self.start_smtp_server())
            self.loop.run_until_complete(self.smtp_task)
        except asyncio.CancelledError:
            logger.info("SMTP server task was cancelled")
        except Exception as e:
            if not self.shutdown_requested:
                logger.error(f"SMTP server thread error: {e}")
        finally:
            if self.loop:
                self.loop.close()
    
    def run(self, smtp_only=False, web_only=False, debug=False, host='127.0.0.1', port=5000):
        """Run the unified application"""
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
            if self.loop:
                self.loop.call_soon_threadsafe(self._stop_smtp_server)


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
            app.init_sample_data()
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

Available web routes:
  • /                     → Dashboard
  • /email/domains        → Domain management
  • /email/users          → User management
  • /email/ips            → IP whitelist management
  • /email/dkim           → DKIM management
  • /email/settings       → Server settings
  • /email/logs           → Server logs
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


if __name__ == '__main__':
    main()
