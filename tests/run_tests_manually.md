## setup domain and account for sending email:
```bash
# Manual Test Setup Instructions

## Setup via Web Interface
1. Start the application: `python app.py`
2. Open web browser to: http://localhost:5000/email
3. Use the web interface to:
   - Add domain: example.com
   - Add user: test@example.com with password testpass123
   - Add IP whitelist: 127.0.0.1 and 10.100.111.1 for domain example.com
   - Generate DKIM key for example.com

## Alternative Setup via Python Script
Create a setup script if needed for automated testing.
```

## Check db logs
`sqlite3 smtp_server.db "SELECT message_id, rcpt_tos, status FROM email_logs;"`

## Send emails using python script:
`python tests/send_email.py --port=4025 --porttls=40587 --recipient 'info@example.com'`

## Linux send emails using `swaks`
```bash
# multiline test with body from the email_body.txt file:
swaks --to info@example.com \
      --from test@example.com \
      --server localhost \
      --port 40587 \
      --auth LOGIN \
      --auth-user test@example.com \
      --auth-password testpass123 \
      --tls \
      --header "Subject: This is the subject" \
      --body @tests/email_body.txt

swaks --to info@example.com \
      --from test@example.com \
      --server localhost \
      --port 4025 \
      --auth LOGIN \
      --auth-user test@example.com \
      --auth-password testpass123 \
      --data "Subject: Test Email - authenticated\n\nThis is the message body."

swaks --to info@example.com \
      --from test@example.com \
      --server localhost \
      --port 40587 \
      --auth LOGIN \
      --auth-user test@example.com \
      --auth-password testpass123 \
      --tls \
      --data "Subject: Test via STARTTLS - authenticated\n\nThis is the body."

swaks --to info@example.com \
      --from test@example.com \
      --server localhost \
      --port 40587 \
      --tls \
      --data "Subject: Test via STARTTLS - no auth\n\nThis is the body."

swaks --to info@example.com \
      --from test@example.com \
      --server localhost \
      --port 4025 \
      --data "Subject: Test Email - no auth\n\nThis is the message body."
```