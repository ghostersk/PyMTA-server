#!/bin/bash
# apt-get install -y swaks
receiver="info@example.com"
EMAIL_SERVER="localhost"   #"pymta.example.com" "localhost"
EMAIL_SERVER_auth="10.100.111.1"   # IP for authenticated server ( not localhost), use your main interface ip

sender="test@example.com"
username="test@example.com"
password="ZjDvcjPSs-nwK2Ghj5vQY7L4LdmTpmn_AEZMokJTFS"  # password you setup for the user!
domain="example.com"
body_content_file="@tests/email_body.txt"
SMTP_PORT=4025
SMTP_TLS_PORT=40465
cc_recipient="ccrecipient@example.com"
bcc_recipient="bccrecipient@example.com"

<<com

# options to add CC and BCC recipients for swaks
      --cc $cc_recipient \
      --bcc $bcc_recipient \
      --header "To: $receiver" \
      --header "Cc: $cc_recipient" \

swaks --to $receiver \
      --from $sender \
      --server $EMAIL_SERVER \
      --port $SMTP_TLS_PORT \
      --auth LOGIN \
      --auth-user $username \
      --auth-password $password \
      --tls \
      --header "Subject: TLS - Large body email" \
      --body "simple body content" \
      --attach @/home/nahaku/Documents/Projects/SMTP_Server/tests/pdf_test_1.pdf \
      --attach @/home/nahaku/Documents/Projects/SMTP_Server/tests/note_authentication_order_fix.md
      #--attach @/home/nahaku/Documents/Projects/SMTP_Server/tests/Hello.jpg
      #--attach @/home/nahaku/Documents/Projects/SMTP_Server/tests/email_body.txt

com
<<com 

com
swaks --to $receiver \
      --from $sender \
      --server $EMAIL_SERVER \
      --port $SMTP_PORT \
      --auth LOGIN \
      --auth-user $username \
      --auth-password $password \
      --data "Subject: SMTP - authenticated success\n\nThis is the message body."

# Test with Authentication TLS
swaks --to $receiver \
      --from $sender \
      --server $EMAIL_SERVER \
      --port $SMTP_TLS_PORT \
      --auth LOGIN \
      --auth-user $username \
      --auth-password $password \
      --tls \
      --header "Subject: TLS - authenticated success" \
      --body "This is the message body with proper headers."

# Test TLS + authentication and IP whitelist
swaks --to $receiver \
      --from $sender \
      --server $EMAIL_SERVER_auth \
      --port $SMTP_TLS_PORT \
      --auth LOGIN \
      --auth-user $username \
      --auth-password $password \
      --tls \
      --data "Subject: TLS - auth + IP Whitelist \n\nTest TLS + authentication and IP whitelist"


# Test with IP authentication TLS
swaks --to $receiver \
      --from $sender \
      --server $EMAIL_SERVER_auth \
      --port $SMTP_TLS_PORT \
      --tls \
      --data "Subject: TLS - IP Whitelist - no auth\n\nTest with IP authentication TLS"

# Test with IP authentication SMTP
swaks --to $receiver \
      --from $sender \
      --server $EMAIL_SERVER_auth \
      --port $SMTP_PORT \
      --data "Subject: SMTP - IP Whitelist - no auth\n\nTest with IP authentication SMTP"


<<com
com
# SMTP un-auth test "Email_server - no Whitelist - no auth"
swaks --to $receiver \
      --from $sender \
      --server $EMAIL_SERVER \
      --port $SMTP_PORT \
      --data "Subject: SMTP - no Whitelist - no auth\n\nSMTP un-auth test Email_server - no Whitelist - no auth."

# Test TLS un-auth test "Email_server - no Whitelist - no auth"
swaks --to $receiver \
      --from $sender \
      --server $EMAIL_SERVER \
      --port $SMTP_TLS_PORT \
      --tls \
      --data "Subject: TLS - no Whitelist - no auth\n\nTest TLS un-auth test Email_server - no Whitelist - no auth"