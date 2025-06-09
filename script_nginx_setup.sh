#!/bin/bash

# Configuration variables
DOMAIN="example.com"  # Replace with your domain (e.g., example.com)
WEBSITE_URL="mail.example.com" # Replace with website URL for web interface
EMAIL="admin@example.com"  # Replace with your email for Let's Encrypt
LETSENCRYPT_EXPORT_PATH="/opt/PyMTA-server/email_server/ssl_certs/"  # Path to export .crt and .key files
APP_USERNAME="appuser" # Replace with the username of the user running the SMTP app
NGINX_CONF_DIR="/etc/nginx"
SITES_AVAILABLE="$NGINX_CONF_DIR/sites-available/$DOMAIN"
SITES_ENABLED="$NGINX_CONF_DIR/sites-enabled/$DOMAIN"
SITE_APP="$NGINX_CONF_DIR/sites-enabled/$WEBSITE_URL"
WEB_ROOT="/var/www/$DOMAIN/html"
ERROR_PAGE_DIR="$WEB_ROOT/errors"
CLOUDFLARE_DNS_PLUGIN="certbot-dns-cloudflare"
# https://medium.com/@life-is-short-so-enjoy-it/homelab-nginx-proxy-manager-setup-ssl-certificate-with-domain-name-in-cloudflare-dns-732af64ddc0b
CLOUDFLARE_API_TOKEN_HERE="" # <<<< Set up here your cloudflare API token 
CLOUDFLARE_CREDENTIALS="/root/.cloudflare/credentials.ini"
VENV_DIR="/opt/certbot-venv"

# Exit on error
set -e

# List of common HTTP error codes with brief messages
# hides Nginx error pages for custom
declare -A ERROR_MESSAGES=(
    [400]="Bad Request"
    [401]="Unauthorized"
    [403]="Forbidden"
    [404]="Not Found"
    [500]="Internal Server Error"
    [502]="Bad Gateway"
    [503]="Service Unavailable"
    [504]="Gateway Timeout"
)

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root or with sudo" >&2
   exit 1
fi

# Update system and install required packages
echo "Updating system and installing dependencies..."
apt update && apt upgrade -y
apt install -y nginx certbot python3 python3-pip python3-venv python3-dev

# Create and activate a virtual environment for certbot-dns-cloudflare
echo "Creating Python virtual environment for certbot-dns-cloudflare..."
mkdir -p "$VENV_DIR"
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

# Upgrade pip in the virtual environment
echo "Upgrading pip..."
pip3 install --upgrade pip

# Install Cloudflare DNS plugin for Certbot
echo "Installing certbot-dns-cloudflare..."
if ! pip3 install "$CLOUDFLARE_DNS_PLUGIN"; then
    echo "Failed to install $CLOUDFLARE_DNS_PLUGIN. Please check your network or Python environment." >&2
    deactivate
    exit 1
fi

# Deactivate virtual environment
deactivate

# Create web root and error page directory
echo "Creating web root and error page directories..."
mkdir -p "$WEB_ROOT" "$ERROR_PAGE_DIR"

# Generate HTML files for each error code
for code in "${!ERROR_MESSAGES[@]}"; do
    file="$ERROR_PAGE_DIR/$code.html"
    cat > "$file" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>Error $code</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        h1 { font-size: 48px; color: #c00; }
        p { font-size: 20px; color: #666; }
        a { text-decoration: none; color: #007acc; }
    </style>
</head>
<body>
    <h1>Error $code</h1>
    <p>${ERROR_MESSAGES[$code]}</p>
    <p><a href="/">Return to Home</a></p>
</body>
</html>
EOF
    echo "Created: $file"
done

echo "All error pages generated in $ERROR_PAGE_DIR"

# Set permissions for error page
chown -R www-data:www-data "$WEB_ROOT"
chmod -R 755 "$WEB_ROOT"

# Create Cloudflare credentials file (ensure you replace with your actual API token)
echo "Creating Cloudflare credentials file..."
mkdir -p "$(dirname "$CLOUDFLARE_CREDENTIALS")"
cat > "$CLOUDFLARE_CREDENTIALS" << EOF
dns_cloudflare_api_token = $CLOUDFLARE_API_TOKEN_HERE
EOF
chmod 600 "$CLOUDFLARE_CREDENTIALS"

# Create NGINX configuration
echo "Creating NGINX configuration for $DOMAIN..."
mkdir -p "$NGINX_CONF_DIR/sites-available" "$NGINX_CONF_DIR/sites-enabled"
cat > "$SITES_AVAILABLE" << EOF
server {
    listen 80;
    server_name $DOMAIN *.$DOMAIN;

    root $WEB_ROOT;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    error_page 404 $ERROR_PAGE;
    location = $ERROR_PAGE {
        root $WEB_ROOT;
        internal;
    }
}
EOF

# Enable the site
ln -sf "$SITES_AVAILABLE" "$SITES_ENABLED"
# Disable default site
rm -f "$NGINX_CONF_DIR/sites-enabled/default"

# Test NGINX configuration
echo "Testing NGINX configuration..."
nginx -t

# Reload NGINX to apply changes
echo "Reloading NGINX..."
systemctl reload nginx


# Obtain Let's Encrypt wildcard SSL certificate using Cloudflare DNS
echo "Obtaining Let's Encrypt wildcard SSL certificate..."
source "$VENV_DIR/bin/activate"
if ! certbot certonly \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$CLOUDFLARE_CREDENTIALS" \
        --domains "$DOMAIN,*.$DOMAIN"; then
    echo "Failed to obtain Let's Encrypt certificate. Please check Cloudflare credentials and DNS settings." >&2
    deactivate
    exit 1
fi
deactivate

# Export .crt and .key files to LETSENCRYPT_EXPORT_PATH
echo "Exporting SSL certificate and key to $LETSENCRYPT_EXPORT_PATH..."
mkdir -p "$LETSENCRYPT_EXPORT_PATH"
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$LETSENCRYPT_EXPORT_PATH/server.crt"
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$LETSENCRYPT_EXPORT_PATH/server.key"
chown $APP_USERNAME:$APP_USERNAME "$LETSENCRYPT_EXPORT_PATH/server.crt" "$LETSENCRYPT_EXPORT_PATH/server.key"
chmod 600 "$LETSENCRYPT_EXPORT_PATH/server.crt" "$LETSENCRYPT_EXPORT_PATH/server.key"

# Update NGINX configuration to use SSL
echo "Updating NGINX configuration for SSL..."
cat > "$SITES_AVAILABLE" << EOF
# Hide NGINX server signature
server_tokens off;

server {
    listen 80 default_server;
    server_name _;

    root $WEB_ROOT;
    index errors/404.html; #index.html;

    error_page 400 /errors/400.html;
    error_page 401 /errors/401.html;
    error_page 403 /errors/403.html;
    error_page 404 /errors/404.html;
    error_page 500 /errors/500.html;
    error_page 502 /errors/502.html;
    error_page 503 /errors/503.html;
    error_page 504 /errors/504.html;
    location /errors/ {
        root $WEB_ROOT;
        internal;
    }   
}

server {
    listen 443 ssl default_server;
    server_name _;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    # SSL security settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    root $WEB_ROOT;
    index errors/404.html; #index.html;

    error_page 400 /errors/400.html;
    error_page 401 /errors/401.html;
    error_page 403 /errors/403.html;
    error_page 404 /errors/404.html;
    error_page 500 /errors/500.html;
    error_page 502 /errors/502.html;
    error_page 503 /errors/503.html;
    error_page 504 /errors/504.html;
    location /errors/ {
        root $WEB_ROOT;
        internal;
    }
}

server {
    listen 80;
    server_name $WEBSITE_URL;
    # Prevent redirect loop with Cloudflare
    if ($http_x_forwarded_proto = "http") {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name $WEBSITE_URL;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    # SSL security settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # Proxy settings for Flask app
    location / {
        proxy_pass http://127.0.0.1:5000; # Updated this, where runs your web interface
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
EOF

# Test NGINX configuration again
echo "Testing updated NGINX configuration..."
nginx -t

# Reload NGINX to apply SSL changes
echo "Reloading NGINX with SSL configuration..."
systemctl reload nginx

# Enable NGINX auto-start
echo "Enabling NGINX to start on boot..."
systemctl enable nginx

# Set up automatic certificate renewal
echo "Setting up Let's Encrypt renewal for wildcard certificate..."
(crontab -l 2>/dev/null; echo "0 3 * * * /opt/certbot-venv/bin/certbot renew --quiet && \\
  cp /etc/letsencrypt/live/\$DOMAIN/fullchain.pem \$LETSENCRYPT_EXPORT_PATH/server.crt && \\
  cp /etc/letsencrypt/live/\$DOMAIN/privkey.pem \$LETSENCRYPT_EXPORT_PATH/server.key && \\
  chown \$APP_USERNAME:\$APP_USERNAME "\$LETSENCRYPT_EXPORT_PATH/server.crt" "\$LETSENCRYPT_EXPORT_PATH/server.key" && \\
  chmod 600 \$LETSENCRYPT_EXPORT_PATH/server.crt \$LETSENCRYPT_EXPORT_PATH/server.key") | crontab -

echo "NGINX setup complete! Your site is live at https://$DOMAIN"
echo "Wildcard certificate covers *.$DOMAIN"
echo "Custom 404 page is set at $ERROR_PAGE"
echo "SSL certificate and key exported to $LETSENCRYPT_EXPORT_PATH"
echo "Please ensure your Cloudflare API token is correctly set in $CLOUDFLARE_CREDENTIALS"