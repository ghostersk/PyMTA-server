## setup domain and account for sending email:
```bash
python -m email_server.cli_tools.py add-domain example.com
python -m email_server.cli_tools.py add-user test@example.com testpass123 example.com
python -m email_server.cli_tools.py add-ip 127.0.0.1 example.com 
python -m email_server.cli_tools.py add-ip 10.100.111.1 example.com 
python -m email_server.cli_tools.py generate-dkim example.com
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