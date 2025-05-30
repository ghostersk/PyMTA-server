
## Check db logs
`sqlite3 smtp_server.db "SELECT message_id, rcpt_tos, status FROM email_logs;"`

## Send emails using python script:
`python tests/send_email.py --port=4025 --porttls=40587 --recipient 'info@example.com'`

## Linux send emails using `swaks`
```bash
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