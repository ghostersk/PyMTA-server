# SMTP Server Management Frontend

A comprehensive Flask-based web interface for managing SMTP server operations, including domain management, user authentication, DKIM configuration, IP whitelisting, and email monitoring.

## Features

### 🏠 Dashboard
- Server statistics and health monitoring  
- Recent activity overview
- Quick access to all management sections
- Real-time server status indicators

### 🌐 Domain Management
- Add, edit, and remove domains
- Domain status monitoring
- Bulk domain operations
- Domain-specific statistics

### 👥 User Management
- Create and manage email users
- Password management
- Domain-based user organization
- User permission levels (regular user vs domain admin)
- Email validation and verification

### 🔒 IP Whitelist Management
- Add/remove whitelisted IP addresses
- Support for single IPs and CIDR notation
- Current IP detection
- Domain-specific IP restrictions
- Security notes and best practices

### 🔐 DKIM Management
- Generate and manage DKIM keys
- DNS record verification
- SPF record management
- Real-time DNS checking
- Copy-to-clipboard functionality for DNS records

### ⚙️ Server Settings
- Configure all server parameters via web interface
- Real-time settings.ini file updates
- Settings validation and error checking
- Export/import configuration
- Sections: Server, Database, Logging, Relay, TLS, DKIM

### 📊 Logs & Monitoring
- Email logs with detailed filtering
- Authentication logs
- Error tracking and debugging
- Real-time log updates
- Export log data
- Advanced search and filtering

## Installation

### Prerequisites

- Python 3.9 or higher
- Flask 2.3+
- Access to the SMTP server database
- Web browser with JavaScript enabled

### Setup

1. **Clone or navigate to the SMTP server directory:**
   ```bash
   cd /path/to/SMTP_Server
   ```

2. **Install frontend dependencies:**
   ```bash
   # Create virtual environment if it doesn't exist
   python3 -m venv .venv
   
   # Activate virtual environment
   source .venv/bin/activate  # Linux/macOS
   # or
   .venv\Scripts\activate     # Windows
   
   # Install frontend requirements
   .venv/bin/pip install -r email_frontend/requirements.txt
   ```

3. **Initialize sample data (optional):**
   ```bash
   .venv/bin/python email_frontend/example_app.py --init-data
   ```

4. **Run the example application:**
   ```bash
   .venv/bin/python email_frontend/example_app.py
   ```

5. **Access the web interface:**
   Open your browser and navigate to `http://127.0.0.1:5000`

## Integration

### Using as a Flask Blueprint

The frontend is designed as a Flask Blueprint that can be integrated into existing Flask applications:

```python
from flask import Flask
from email_frontend.blueprint import email_bp

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///smtp_server.db'

# Register the blueprint
app.register_blueprint(email_bp, url_prefix='/email')

if __name__ == '__main__':
    app.run(debug=True)
```

### Blueprint Routes

The blueprint provides the following routes under the `/email` prefix:

- `/` or `/dashboard` - Main dashboard
- `/domains` - Domain management
- `/domains/add` - Add new domain
- `/users` - User management  
- `/users/add` - Add new user
- `/ips` - IP whitelist management
- `/ips/add` - Add whitelisted IP
- `/dkim` - DKIM management
- `/settings` - Server configuration
- `/logs` - Email and authentication logs

### Configuration

The frontend requires access to your SMTP server's database and configuration files:

1. **Database Access:** Ensure the Flask app can connect to your SMTP server database
2. **Settings File:** The frontend reads from `settings.ini` in the project root
3. **Static Files:** CSS and JavaScript files are served from `email_frontend/static/`

## Customization

### Templates

All templates extend `base.html` and use the dark Bootstrap theme. Key templates:

- `base.html` - Base layout with navigation
- `sidebar_email.html` - Navigation sidebar
- `email/dashboard.html` - Main dashboard
- `email/*.html` - Feature-specific pages

### Styling

Custom CSS is located in `static/css/smtp-management.css` and includes:

- Dark theme enhancements
- Custom form styling
- DNS record display formatting
- Log entry styling
- Responsive design tweaks

### JavaScript

Interactive features are implemented in `static/js/smtp-management.js`:

- Form validation
- AJAX requests for DNS checking
- Copy-to-clipboard functionality
- Auto-refresh for logs
- Real-time IP detection

## API Endpoints

The frontend provides several AJAX endpoints for enhanced functionality:

### DNS Verification
```
POST /email/check-dns
Content-Type: application/json

{
    "domain": "example.com",
    "record_type": "TXT", 
    "expected_value": "v=DKIM1; k=rsa; p=..."
}
```

### Settings Updates
```
POST /email/settings
Content-Type: application/x-www-form-urlencoded

section=server&key=smtp_port&value=587
```

### Log Filtering  
```
GET /email/logs?filter=email&page=1&per_page=50
```

## Security Considerations

### Authentication
- Implement proper authentication before deploying to production
- Use strong session keys
- Consider implementing role-based access control

### Network Security
- Run behind a reverse proxy (nginx/Apache) in production
- Use HTTPS for all connections
- Implement rate limiting
- Restrict access to management interface

### Data Protection
- Sanitize all user inputs
- Use parameterized queries
- Implement CSRF protection
- Regular security updates

## Development

### Project Structure
```
email_frontend/
├── __init__.py              # Package initialization
├── blueprint.py             # Main Flask Blueprint
├── example_app.py           # Example Flask application
├── requirements.txt         # Python dependencies
├── static/                  # Static assets
│   ├── css/
│   │   └── smtp-management.css
│   └── js/
│       └── smtp-management.js
└── templates/               # Jinja2 templates
    ├── base.html           # Base template
    ├── sidebar_email.html  # Navigation sidebar
    └── email/              # Feature templates
        ├── dashboard.html
        ├── domains.html
        ├── users.html
        ├── ips.html
        ├── dkim.html
        ├── settings.html
        ├── logs.html
        └── error.html
```

### Adding New Features

1. **Add routes to `blueprint.py`**
2. **Create corresponding templates in `templates/email/`**
3. **Update navigation in `sidebar_email.html`**
4. **Add custom styling to `smtp-management.css`**
5. **Implement JavaScript interactions in `smtp-management.js`**

### Testing

Run the example application with debug mode:

```bash
.venv/bin/python email_frontend/example_app.py --debug
```

Initialize test data:

```bash
.venv/bin/python email_frontend/example_app.py --init-data
```

## Troubleshooting

### Common Issues

**Database Connection Errors:**
- Verify database file exists and is accessible
- Check file permissions
- Ensure SQLAlchemy is properly configured

**Template Not Found Errors:**
- Verify templates are in the correct directory structure
- Check template inheritance and block names
- Ensure blueprint is registered with correct static folder

**Static Files Not Loading:**
- Check Flask static file configuration
- Verify CSS/JS files exist in static directories
- Clear browser cache

**DNS Verification Not Working:**
- Ensure `dnspython` is installed
- Check network connectivity
- Verify DNS server accessibility

### Debug Mode

Enable debug mode for detailed error information:

```python
app.run(debug=True)
```

Or via command line:
```bash
.venv/bin/python email_frontend/example_app.py --debug
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is part of the SMTP Server suite. Please refer to the main project license.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the example application
3. Create an issue in the project repository

---

**Note:** This frontend is designed specifically for the SMTP Server project and requires the associated database models and configuration files to function properly.
