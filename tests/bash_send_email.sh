#!/bin/bash
sender="test@example.com"
receiver="info@example.com"
password="testpass123"
domain="example.com"
body_content_file="@tests/email_body.txt"
SMTP_PORT=4025
SMTP_TLS_PORT=40587
cc_recipient="targetcc@example.com"
bcc_recipient="targetbcc@example.com"

<<com
# Setup domain and user via web interface first
# Visit http://localhost:5000/email to configure:
# - Add domain: $domain
# - Add user: $sender with password $password
# - Add IP whitelist: 127.0.0.1 and 10.100.111.1
# - Generate DKIM key for domain

# options to add CC and BCC recipients for swaks
      --cc $cc_recipient
      --bcc $bcc_recipient
com

swaks --to $receiver \
      --from $sender \
      --server localhost \
      --port $SMTP_TLS_PORT \
      --auth LOGIN \
      --auth-user $sender \
      --auth-password $password \
      --tls \
      --header "Subject: TLS - Large body email" \
      --body $body_content_file \
      --attach tests/email_body.txt \
      --attach tests/Hello.jpg

swaks --to $receiver \
      --from $sender \
      --server localhost \
      --port $SMTP_PORT \
      --auth LOGIN \
      --auth-user $sender \
      --auth-password $password \
      --data "Subject: Test Email - authenticated\n\nThis is the message body."

swaks --to $receiver \
      --from $sender \
      --server localhost \
      --port $SMTP_TLS_PORT \
      --auth LOGIN \
      --auth-user $sender \
      --auth-password $password \
      --tls \
      --data "Subject: Test via STARTTLS - authenticated\n\nThis is the body."

swaks --to $receiver \
      --from $sender \
      --server localhost \
      --port $SMTP_TLS_PORT \
      --tls \
      --data "Subject: Test via STARTTLS - no auth\n\nThis is the body."
com

swaks --to $receiver \
      --from $sender \
      --server localhost \
      --port $SMTP_PORT \
      --data "Subject: Test Email - no auth\n\nThis is the message body."