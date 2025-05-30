# ========================================
# SMTP Server Management with cli_tools.py
# ========================================

# 1. Initialize the database (run this first)
`python cli_tools.py init`

# ========================================
# DOMAIN MANAGEMENT
# ========================================

# Add domains that require authentication (default)
```python
python cli_tools.py add-domain example.com
python cli_tools.py add-domain mycompany.org
python cli_tools.py add-domain testdomain.net
```

# Add domain that doesn't require authentication (open relay for this domain)
`python cli_tools.py add-domain public.com --no-auth`

# ========================================
# USER MANAGEMENT (for authentication)
# ========================================

# Add users for authentication
```python
python cli_tools.py add-user test@example.com testpass123 example.com
python cli_tools.py add-user admin@example.com adminpass456 example.com
python cli_tools.py add-user john@mycompany.org johnpass789 mycompany.org
python cli_tools.py add-user support@mycompany.org supportpass321 mycompany.org
```

# Add more test users
```
python cli_tools.py add-user demo@testdomain.net demopass111 testdomain.net
python cli_tools.py add-user sales@example.com salespass222 example.com
```

# ========================================
# IP WHITELIST MANAGEMENT (for IP-based auth)
# ========================================

# Add IP addresses that can send without username/password
```python
python cli_tools.py add-ip 127.0.0.1 example.com          # Localhost
python cli_tools.py add-ip 192.168.1.100 example.com      # Local network
python cli_tools.py add-ip 10.0.0.50 mycompany.org        # Internal server
python cli_tools.py add-ip 203.0.113.10 example.com       # External trusted IP
```

# Add entire local network (if your server supports CIDR - may need modification)
`python cli_tools.py add-ip 192.168.1.0 example.com`        # Network range

# ========================================
# DKIM KEY MANAGEMENT
# ========================================

# Generate DKIM keys for domains (for email signing)
```python
python cli_tools.py generate-dkim example.com
python cli_tools.py generate-dkim mycompany.org
python cli_tools.py generate-dkim testdomain.net
```

# List all DKIM keys
`python cli_tools.py list-dkim`

# Show DNS records that need to be added to your DNS provider
`python cli_tools.py show-dns`

# ========================================
# COMPLETE SETUP EXAMPLE
# ========================================

# Complete setup for a new domain:
```python
python cli_tools.py add-domain newdomain.com
python cli_tools.py add-user info@newdomain.com password123 newdomain.com
python cli_tools.py add-user noreply@newdomain.com noreplypass456 newdomain.com
python cli_tools.py add-ip 192.168.1.200 newdomain.com
python cli_tools.py generate-dkim newdomain.com
```

# ========================================
# VERIFICATION COMMANDS
# ========================================

# Check what's in the database
```bash
sqlite3 smtp_server.db "SELECT * FROM domains;"
sqlite3 smtp_server.db "SELECT email, domain_id FROM users;"
sqlite3 smtp_server.db "SELECT ip_address, domain_id FROM whitelisted_ips;"
sqlite3 smtp_server.db "SELECT domain, selector, active FROM dkim_keys;"
```

# Check email logs
`sqlite3 smtp_server.db "SELECT message_id, mail_from, rcpt_tos, status, created_at FROM email_logs ORDER BY created_at DESC LIMIT 10;"`

# ========================================
# HELP AND INFORMATION
# ========================================

# Show all available commands
`python cli_tools.py --help`

# Show help for specific commands
```python
python cli_tools.py add-domain --help
python cli_tools.py add-user --help
python cli_tools.py add-ip --help
python cli_tools.py generate-dkim --help
```

# ========================================
# PRACTICAL EXAMPLES
# ========================================

# Example 1: Setup for development
```python
python cli_tools.py init
python cli_tools.py add-domain localhost.dev
python cli_tools.py add-user dev@localhost.dev devpass123 localhost.dev
python cli_tools.py add-ip 127.0.0.1 localhost.dev
python cli_tools.py generate-dkim localhost.dev
```

# Example 2: Setup for production company
```python
python cli_tools.py add-domain company.com
python cli_tools.py add-user notifications@company.com notifypass123 company.com
python cli_tools.py add-user alerts@company.com alertpass456 company.com
python cli_tools.py add-ip 10.0.1.100 company.com  # Application server
python cli_tools.py add-ip 10.0.1.101 company.com  # Backup server
python cli_tools.py generate-dkim company.com
```
# Example 3: Setup for testing with external domain
```python
python cli_tools.py add-domain example.org
python cli_tools.py add-user test@example.org testpass789 example.org
python cli_tools.py generate-dkim example.org
python cli_tools.py show-dns  # Get DNS records to add
```
# ========================================
# TROUBLESHOOTING COMMANDS
# ========================================

# If you need to check if everything is set up correctly:
```python
python cli_tools.py list-dkim                          # Verify DKIM keys exist
sqlite3 smtp_server.db "SELECT COUNT(*) FROM domains;" # Count domains
sqlite3 smtp_server.db "SELECT COUNT(*) FROM users;"   # Count users
sqlite3 smtp_server.db "SELECT COUNT(*) FROM whitelisted_ips;" # Count IPs
```

# Check recent email activity
`sqlite3 smtp_server.db "SELECT mail_from, rcpt_tos, status, created_at FROM email_logs WHERE created_at > datetime('now', '-1 hour');"`