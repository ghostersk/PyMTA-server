import smtplib
from email.mime.text import MIMEText
import ssl
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, default=4025)
parser.add_argument('--porttls', type=int, default=40587)
parser.add_argument('--recipient', type=str, default="test@target-email.com")
args = parser.parse_args()

recipient = args.recipient
username='test@example.com'
password='testpass123'


def send_test_email(port=args.port, smtpserver='localhost', use_auth=False, 
        username=None, password=None, subject='SMTP Authentication Test', 
        recipient=args.recipient):
    """Send a test email using plain SMTP."""    
    msg = MIMEText('This is a test email.')
    msg['Subject'] = subject
    msg['From'] = username
    msg['To'] = recipient

    try:
        with smtplib.SMTP(smtpserver, port, timeout=5) as server:
            if use_auth:
                server.login(username, password)
            server.send_message(msg)
        print(f'Email sent {subject}!')
    except Exception as e:
        print(f'Error sending email: {e}')

def send_test_email_tls(port=args.porttls, smtpserver='localhost', use_auth=False, 
        username=None, password=None, subject='StarTTLS Email Test', 
        recipient=args.recipient):
    """Send a test email using STARTTLS."""
    msg = MIMEText('This is a test email over TLS.')
    msg['Subject'] = subject
    msg['From'] = username
    msg['To'] = recipient
    context = ssl._create_unverified_context()
    server = None

    try:
        server = smtplib.SMTP(smtpserver, port, timeout=5)
        #server.set_debuglevel(2)
        server.ehlo()
        if server.has_extn('STARTTLS'):
            server.starttls(context=context)
            server.ehlo()
        else:
            print("Server does not support STARTTLS")
            return
        if use_auth:
            server.login(username, password)
            server.send_message(msg)
            print(f'Email sent {subject}!')
        else:
            server.send_message(msg)
            print(f'Email sent {subject}!')
    except Exception as e:
        print(f"Error sending TLS email: {e}")
    finally:
        if server:
            try:
                server.quit()
            except:
                pass


if __name__ == '__main__':
    # SMTP Authenticated test:
    send_test_email(port=args.port, use_auth=True, username=username, password=password, recipient=recipient, subject='SMTP Authenticated Email Test')
    # SMTP IP Whitelisted test:
    send_test_email(port=args.port, username=username, recipient=recipient, subject='SMTP IP Whitelisted Test')
    # SMTP Bad Credentials test:
    send_test_email(port=args.port, use_auth=True, username='usser@example.com', password='badpasssw', recipient=recipient, subject='SMTP Bad Credentials')

    # TLS IP Whitelisted test:
    send_test_email_tls(port=args.porttls, username=username, recipient=recipient, subject='StarTTLS IP Whitelisted Test')
    # TLS Authenticated test:
    send_test_email_tls(port=args.porttls, use_auth=True, username=username, password=password, recipient=recipient, subject='StarTTLS Authenticated Email Test')
    # TLS Bad Credentials test:
    send_test_email_tls(port=args.porttls, use_auth=True, username='usser@example.com', password='badpasssw', recipient=recipient,subject='StarTTLS Bad Credentials Test')
