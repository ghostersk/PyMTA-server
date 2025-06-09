# SMTP Server with Web Management Frontend

A comprehensive SMTP server with an integrated Flask-based web management interface. This application provides both a fully functional SMTP server and a modern web interface for managing domains, users, DKIM keys, and server settings.

## Features

### SMTP Server
- **Full SMTP Server**: Send and receive emails with authentication
- **DKIM Support**: Automatic DKIM key generation and email signing
- **TLS/SSL Encryption**: Secure email transmission
- **Domain Management**: Support for multiple domains
- **User Authentication**: Per-user and per-domain authentication
- **IP Whitelisting**: Allow specific IPs to send without authentication
- **Email Relay**: Forward emails to external servers
- **Comprehensive Logging**: Track all email and authentication activities

### Web Management Interface
- **Modern Dark UI**: Bootstrap-based responsive interface
- **Domain Management**: Add, configure, and manage email domains
- **User Management**: Create and manage email users with permissions
- **DKIM Management**: Generate keys, view DNS records, verify setup
- **IP Whitelist Management**: Configure IP-based access controls
- **Server Settings**: Web-based configuration management
- **Real-time Logs**: View email and authentication logs with filtering
- **DNS Verification**: Built-in DNS record checking for DKIM and SPF
- **Health Monitoring**: Server status and performance metrics

## Quick Start

### Prerequisites
- Python 3.9 or higher
- Linux/macOS (Windows with WSL)

### Installation

1. **Clone or navigate to the project directory:**
   ```bash
   cd /home/nahaku/Documents/Projects/SMTP_Server
   ```

2. **Run the setup script:**
   ```bash
   chmod +x email_frontend/setup.sh
   ./email_frontend/setup.sh
   ```

3. **Initialize sample data (optional):**
   ```bash
   .venv/bin/python app.py --init-data
   ```

4. **Start the unified application:**
   ```bash
   .venv/bin/python app.py
   ```

The application will start both the SMTP server and web interface:
- **Web Interface**: http://127.0.0.1:5000
- **SMTP Server**: Port 25 (plain), Port 587 (TLS)

## Usage Modes

### Unified Mode (Default)
Run both SMTP server and web interface together:
```bash
.venv/bin/python app.py
```

### SMTP Server Only
Run only the SMTP server without web interface:
```bash
.venv/bin/python app.py --smtp-only
```

### Web Frontend Only
Run only the web management interface:
```bash
.venv/bin/python app.py --web-only
```

### Development Mode
Enable debug mode with auto-reload:
```bash
.venv/bin/python app.py --debug
```

### Custom Host and Port
Specify custom web server settings:
```bash
.venv/bin/python app.py --host 0.0.0.0 --port 8080
```

## Configuration

### Main Configuration File: `settings.ini`

The server uses a comprehensive configuration file with the following sections:

#### Server Settings
```ini
[Server]
SMTP_PORT = 25
SMTP_TLS_PORT = 587
hostname = your-domain.com
BIND_IP = 0.0.0.0
helo_hostname = your-domain.com
```

#### Database Settings
```ini
[Database]
database_path = email_server/server_data/smtp_server.db
```

#### TLS/SSL Settings
```ini
[TLS]
enable_tls = true
cert_file = email_server/ssl_certs/server.crt
key_file = email_server/ssl_certs/server.key
```

#### DKIM Settings
```ini
[DKIM]
enable_dkim = true
default_selector = default
key_size = 2048
```

### Web Interface Configuration

The web interface can be configured through the settings page or by editing `settings.ini`. Changes require a server restart to take effect.

## Web Interface Features

### Dashboard
- Server status overview
- Domain, user, and DKIM key counts
- Recent email and authentication activity
- Quick access to all management functions

### Domain Management
- Add and remove email domains
- Enable/disable domains
- Automatic DKIM key generation
- Domain-specific settings

### User Management
- Create email users with passwords
- Assign users to domains
- Set user permissions (regular user vs domain admin)
- Manage user access levels

### DKIM Management
- View and generate DKIM keys
- DNS record display with copy-to-clipboard
- Real-time DNS verification
- SPF record recommendations
- Selector management

### IP Whitelist Management
- Add IP addresses or ranges
- Domain-specific whitelisting
- Current IP detection
- Use case documentation

### Server Settings
- Web-based configuration editor
- All settings sections accessible
- Form validation and help text
- Export/import configuration

### Logs and Monitoring
- Real-time email logs
- Authentication logs
- Filtering and pagination
- Auto-refresh functionality
- Error details and troubleshooting

## API Endpoints

The web interface provides REST API endpoints for integration:

### Health Check
```
GET /health
```
Returns server health status and basic information.

### Server Status
```
GET /api/server/status
```
Returns detailed server status including SMTP server state, database counts, and configuration.

### Server Restart
```
POST /api/server/restart
```
Restarts the SMTP server component.

## Database Schema

The application uses SQLite with the following main tables:
- **domains**: Email domain configuration
- **users**: User accounts and authentication
- **whitelisted_ips**: IP-based access control
- **dkim_keys**: DKIM signing keys
- **email_logs**: Email transaction records
- **auth_logs**: Authentication attempts
- **custom_headers**: Custom email headers

## Security Features

### Authentication
- User-based authentication for email sending
- Domain-specific user management
- IP-based whitelisting
- Secure password hashing

### Email Security
- DKIM signing for email authentication
- SPF record support and verification
- TLS encryption for secure transmission
- DNS record validation

### Web Interface Security
- Session management
- CSRF protection
- Input validation and sanitization
- Secure configuration handling

## DNS Configuration

### Required DNS Records

For each domain, configure the following DNS records:

#### DKIM Record
```
default._domainkey.yourdomain.com. IN TXT "v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY"
```

#### SPF Record
```
yourdomain.com. IN TXT "v=spf1 ip4:YOUR_SERVER_IP ~all"
```

#### MX Record
```
yourdomain.com. IN MX 10 your-server.com.
```

The web interface provides the exact DNS records needed and can verify their configuration.

## Troubleshooting

### Common Issues

#### Port Permission Issues
If you get permission denied errors on ports 25 or 587:
```bash
sudo setcap 'cap_net_bind_service=+ep' .venv/bin/python
```

#### Database Issues
Reset the database:
```bash
rm email_server/server_data/smtp_server.db
.venv/bin/python app.py --init-data
```

#### SSL Certificate Issues
Generate new self-signed certificates:
```bash
.venv/bin/python -c "from email_server.tls_utils import generate_self_signed_cert; generate_self_signed_cert()"
```

#### DNS Verification Fails
- Ensure DNS records are properly configured
- Wait for DNS propagation (up to 24 hours)
- Check with online DNS checkers
- Verify your domain's nameservers

### Log Files

Check logs for detailed error information:
- **Application logs**: Console output or systemd logs
- **Email logs**: Available in web interface
- **Authentication logs**: Available in web interface

### Web Interface Issues

If the web interface is not accessible:
1. Check that Flask is running on the correct host/port
2. Verify firewall settings
3. Check browser console for JavaScript errors
4. Review Flask application logs

## Development

### Project Structure
```
├── app.py                      # Unified application entry point
├── main.py                     # SMTP server only entry point
├── settings.ini                # Configuration file
├── requirements.txt            # Python dependencies
├── email_server/               # SMTP server implementation
│   ├── models.py              # Database models
│   ├── smtp_handler.py        # SMTP protocol handling
│   ├── dkim_manager.py        # DKIM key management
│   ├── settings_loader.py     # Configuration loader
│   └── ...
├── email_frontend/             # Web management interface
│   ├── blueprint.py           # Flask Blueprint
│   ├── templates/             # HTML templates
│   ├── static/               # CSS/JS assets
│   └── ...
└── tests/                     # Test files
```

### Adding Features

To add new features to the web interface:

1. **Add routes** to `email_frontend/blueprint.py`
2. **Create templates** in `email_frontend/templates/`
3. **Add static assets** in `email_frontend/static/`
4. **Update navigation** in `sidebar_email.html`

### Testing

Run tests manually:
```bash
cd tests
./custom_test.sh
```

Send test emails:
```bash
.venv/bin/python tests/send_email.py
```

## Production Deployment

### Systemd Service

Create a systemd service for production deployment:

```ini
[Unit]
Description=SMTP Server with Web Management
After=network.target

[Service]
Type=simple
User=smtp-user
WorkingDirectory=/path/to/SMTP_Server
ExecStart=/path/to/SMTP_Server/.venv/bin/python app.py --host 0.0.0.0
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Reverse Proxy

For production web interface, use nginx or Apache as a reverse proxy:

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### Security Considerations

1. **Change default secrets** in configuration
2. **Use proper SSL certificates** for web interface
3. **Configure firewall** to restrict access
4. **Regular backups** of database and configuration
5. **Monitor logs** for suspicious activity
6. **Keep dependencies updated**

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review log files for error details
3. Verify DNS and network configuration
4. Test with sample data using `--init-data`

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please:
1. Follow the existing code style
2. Add tests for new features
3. Update documentation
4. Submit pull requests for review

---

**Note**: This application is designed for educational and development purposes. For production use, ensure proper security configuration, monitoring, and maintenance.
