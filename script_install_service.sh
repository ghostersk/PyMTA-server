#!/bin/bash
SMTP_SERVICE_NAME="pymta-smtp.service"
WEB_SERVICE_NAME="pymta-web.service"
APP_ROOT_FOLDER="" #/opt/PyMTA-server

# Set APP_ROOT_FOLDER to the directory where this script is located if not already set
if [[ -z "$APP_ROOT_FOLDER" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    APP_ROOT_FOLDER="$SCRIPT_DIR"
fi

SCRIPT_MODE="install"
TARGET_USER="$USER"
IS_SYSTEM=false

# Function to print usage
usage() {
    echo "Usage:"
    echo "  $0                     Install as current user"
    echo "  $0 -u username         Install as system service for given user (requires sudo)"
    echo "  $0 -rm                 Remove user service for current user ( also works with 'remove')"
    echo "  $0 -rm username        Remove system service for specified user (requires sudo)"
    echo "  $0 -rm system          Remove system service"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -u)
            TARGET_USER="$2"
            IS_SYSTEM=true
            shift 2
            ;;
        -rm)
            SCRIPT_MODE="remove"
            if [[ "$2" ]]; then
                if [[ "$2" == "system" ]]; then
                    IS_SYSTEM=true
                    TARGET_USER=""
                else
                    IS_SYSTEM=true
                    TARGET_USER="$2"
                fi
                shift
            fi
            shift
            ;;
        remove)
            SCRIPT_MODE="remove"
            shift
            ;;
        *)
            usage
            ;;
    esac
done

write_user_services() {
    mkdir -p "$HOME/.config/systemd/user"

    cat > "$HOME/.config/systemd/user/$SMTP_SERVICE_NAME" <<EOF
[Unit]
Description=PyMTA SMTP Server
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_ROOT_FOLDER
Environment=PYTHONUNBUFFERED=1
ExecStart=$APP_ROOT_FOLDER/.venv/bin/python $APP_ROOT_FOLDER/app.py --smtp-only
Restart=always
RestartSec=5
TimeoutStopSec=4
StandardOutput=journal
StandardError=journal
# This needs to be uncommented if you want to bind to ports below 1024
#AmbientCapabilities=CAP_NET_BIND_SERVICE
#CapabilityBoundingSet=CAP_NET_BIND_SERVICE
# This may not be necessary uncommented if you are not binding to ports below 1024
#NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$APP_ROOT_FOLDER
ProtectHome=true

[Install]
WantedBy=default.target
EOF

    cat > "$HOME/.config/systemd/user/$WEB_SERVICE_NAME" <<EOF
[Unit]
Description=PyMTA Web Management (Flask/Gunicorn)
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_ROOT_FOLDER
Environment=PYTHONUNBUFFERED=1
ExecStart=$APP_ROOT_FOLDER/.venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 app:flask_app
Restart=always
RestartSec=5
TimeoutStopSec=4
StandardOutput=journal
StandardError=journal
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$APP_ROOT_FOLDER
ProtectHome=true

[Install]
WantedBy=default.target
EOF

    systemctl --user daemon-reload
    systemctl --user enable "$SMTP_SERVICE_NAME"
    systemctl --user enable "$WEB_SERVICE_NAME"
    systemctl --user start "$SMTP_SERVICE_NAME"
    systemctl --user start "$WEB_SERVICE_NAME"
    echo "Services installed for user $USER."
    echo "To view logs, run:"
    echo "journalctl --user -u $SMTP_SERVICE_NAME -b -f"
    echo "journalctl --user -u $WEB_SERVICE_NAME -b -f"
    echo "To view service status, run:"
    echo "systemctl --user status $SMTP_SERVICE_NAME"
    echo "systemctl --user status $WEB_SERVICE_NAME"
}

remove_user_services() {
    systemctl --user stop "$SMTP_SERVICE_NAME" || true
    systemctl --user stop "$WEB_SERVICE_NAME" || true
    systemctl --user disable "$SMTP_SERVICE_NAME" || true
    systemctl --user disable "$WEB_SERVICE_NAME" || true
    rm -f "$HOME/.config/systemd/user/$SMTP_SERVICE_NAME"
    rm -f "$HOME/.config/systemd/user/$WEB_SERVICE_NAME"
    systemctl --user daemon-reload
    echo "Removed services for user $USER."
}

write_system_services() {
    SERVICE_DIR="/etc/systemd/system"

    sudo tee "$SERVICE_DIR/$SMTP_SERVICE_NAME" > /dev/null <<EOF
[Unit]
Description=PyMTA SMTP Server (system)
After=network.target

[Service]
Type=simple
User=$TARGET_USER
WorkingDirectory=$APP_ROOT_FOLDER
Environment=PYTHONUNBUFFERED=1
ExecStart=$APP_ROOT_FOLDER/.venv/bin/python $APP_ROOT_FOLDER/app.py --smtp-only
Restart=always
RestartSec=5
TimeoutStopSec=4
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
#NoNewPrivileges=true
StandardOutput=journal
StandardError=journal
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$APP_ROOT_FOLDER
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

    sudo tee "$SERVICE_DIR/$WEB_SERVICE_NAME" > /dev/null <<EOF
[Unit]
Description=PyMTA Web (system)
After=network.target

[Service]
Type=simple
User=$TARGET_USER
WorkingDirectory=$APP_ROOT_FOLDER
Environment=PYTHONUNBUFFERED=1
ExecStart=$APP_ROOT_FOLDER/.venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 app:flask_app
Restart=always
RestartSec=5
TimeoutStopSec=4
StandardOutput=journal
StandardError=journal
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$APP_ROOT_FOLDER
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable "$SMTP_SERVICE_NAME"
    sudo systemctl enable "$WEB_SERVICE_NAME"
    sudo systemctl start "$SMTP_SERVICE_NAME"
    sudo systemctl start "$WEB_SERVICE_NAME"
    echo "Installed system services for user $TARGET_USER."
    echo "To view logs, run:"
    echo "journalctl -u $SMTP_SERVICE_NAME -b -f"
    echo "journalctl -u $WEB_SERVICE_NAME -b -f"
    echo "To view service status, run:"
    echo "systemctl status $SMTP_SERVICE_NAME"
    echo "systemctl status $WEB_SERVICE_NAME"
}

remove_system_services() {
    sudo systemctl stop "$SMTP_SERVICE_NAME" || true
    sudo systemctl stop "$WEB_SERVICE_NAME" || true
    sudo systemctl disable "$SMTP_SERVICE_NAME" || true
    sudo systemctl disable "$WEB_SERVICE_NAME" || true
    sudo rm -f "/etc/systemd/system/$SMTP_SERVICE_NAME"
    sudo rm -f "/etc/systemd/system/$WEB_SERVICE_NAME"
    sudo systemctl daemon-reload
    echo "Removed system services."
}

# Main logic
if [[ "$SCRIPT_MODE" == "remove" ]]; then
    if $IS_SYSTEM; then
        remove_system_services
    else
        remove_user_services
    fi
else
    if $IS_SYSTEM; then
        write_system_services
    else
        write_user_services
    fi
fi
