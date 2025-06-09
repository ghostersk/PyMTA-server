# ========================================
# SMTP Server Management via Web Interface
# ========================================

The SMTP Server now uses a web-based management interface instead of CLI tools.

## Starting the Application
```bash
# Start the unified application (SMTP + Web Interface)
python app.py

# Start only the web interface (for management)
python app.py --web-only

# Start only the SMTP server
python app.py --smtp-only
```

## Web Interface Access
- URL: http://localhost:5000/email
- Available management features:
  - Domain management
  - User authentication management  
  - IP whitelist management
  - DKIM key management with DNS validation
  - Email logs and monitoring
  - Server settings configuration

## Management Tasks via Web Interface

### Domain Management
1. Navigate to http://localhost:5000/email/domains
2. Click "Add Domain" to add new domains
3. Configure authentication requirements per domain
4. Enable/disable domains as needed

### User Management  
1. Navigate to http://localhost:5000/email/users
2. Add users for email authentication
3. Associate users with specific domains
4. Enable/disable user accounts

### IP Whitelist Management
1. Navigate to http://localhost:5000/email/ips
2. Add IP addresses for authentication-free sending
3. Associate IPs with specific domains
4. Manage IP access permissions

### DKIM Key Management
1. Navigate to http://localhost:5000/email/dkim
2. Generate DKIM keys automatically when adding domains
3. View DNS records that need to be configured
4. Check DNS propagation status
5. Regenerate keys if needed

## Example Setup Workflow

### Development Setup
1. Start the application: `python app.py --debug`
2. Open browser to: http://localhost:5000/email
3. Add domain: localhost.dev
4. Add user: dev@localhost.dev with password devpass123
5. Add IP: 127.0.0.1 for localhost.dev
6. Generate and configure DKIM key

### Production Setup
1. Start the application: `python app.py`
2. Open browser to: http://localhost:5000/email
3. Add your company domain
4. Add notification/alert users with strong passwords
5. Add your application server IPs to whitelist
6. Generate DKIM keys and update DNS records

## Database Direct Access (if needed)
```bash
# Check domains
sqlite3 email_server/server_data/smtp_server.db "SELECT * FROM domains;"

# Check users  
sqlite3 email_server/server_data/smtp_server.db "SELECT email, domain_id FROM users;"

# Check IP whitelist
sqlite3 email_server/server_data/smtp_server.db "SELECT ip_address, domain_id FROM whitelisted_ips;"

# Check DKIM keys
sqlite3 email_server/server_data/smtp_server.db "SELECT domain, selector, active FROM dkim_keys;"

# Check email logs
sqlite3 email_server/server_data/smtp_server.db "SELECT message_id, mail_from, rcpt_tos, status, created_at FROM email_logs ORDER BY created_at DESC LIMIT 10;"
```