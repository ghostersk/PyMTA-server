#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

python3 --version
python3 -m venv "$SCRIPT_DIR/.venv" --copies # This will copy the Python binary so cap_net_bind_service will work

$SCRIPT_DIR/.venv/bin/pip install -r $SCRIPT_DIR/requirements.txt

echo "Need Sudo for allowing local .venv python to bind to port < 1024 (SMTP uses port 25)"
# Allow binding to port < 1024 (SMTP uses port 25) without use of sudo
for f in $SCRIPT_DIR/.venv/bin/python*; do if sudo setcap 'cap_net_bind_service=+ep' "$f"; then echo "Set CapNetBindService for $(basename "$f")"; fi; done


echo "*******************************************************************"
echo "To starth the app for testing just run in the virtual environment:"
echo "python app.py"
echo "*******************************************************************"
echo "For testing run SMTP server as:"
echo "python app.py --smtp-only --debug"
echo "For testing with web interface run:"
echo "python app.py --web-only --debug"
echo "*******************************************************************"
echo "Gunicorn must run web interface separately, from the SMTP server"
echo "Production Services will run the app as:"
echo "python app.py --smtp-only & gunicorn -w 4 -b 0.0.0.0:5000 app:flask_app"