"""
Command-line tools for managing the SMTP server.
"""

import argparse
import sys
from models import Session, Domain, User, WhitelistedIP, hash_password, create_tables
from dkim_manager import DKIMManager
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def add_domain(domain_name, requires_auth=True):
    """Add a new domain to the database."""
    session = Session()
    try:
        existing = session.query(Domain).filter_by(domain_name=domain_name).first()
        if existing:
            print(f"Domain {domain_name} already exists")
            return False
        
        domain = Domain(domain_name=domain_name, requires_auth=requires_auth)
        session.add(domain)
        session.commit()
        print(f"Added domain: {domain_name}")
        return True
    except Exception as e:
        session.rollback()
        print(f"Error adding domain: {e}")
        return False
    finally:
        session.close()

def add_user(email, password, domain_name):
    """Add a new user to the database."""
    session = Session()
    try:
        domain = session.query(Domain).filter_by(domain_name=domain_name).first()
        if not domain:
            print(f"Domain {domain_name} not found")
            return False
        
        existing = session.query(User).filter_by(email=email).first()
        if existing:
            print(f"User {email} already exists")
            return False
        
        user = User(
            email=email,
            password_hash=hash_password(password),
            domain_id=domain.id
        )
        session.add(user)
        session.commit()
        print(f"Added user: {email}")
        return True
    except Exception as e:
        session.rollback()
        print(f"Error adding user: {e}")
        return False
    finally:
        session.close()

def add_whitelisted_ip(ip_address, domain_name):
    """Add an IP to the whitelist for a domain."""
    session = Session()
    try:
        domain = session.query(Domain).filter_by(domain_name=domain_name).first()
        if not domain:
            print(f"Domain {domain_name} not found")
            return False
        
        existing = session.query(WhitelistedIP).filter_by(ip_address=ip_address).first()
        if existing:
            print(f"IP {ip_address} already whitelisted")
            return False
        
        whitelist = WhitelistedIP(
            ip_address=ip_address,
            domain_id=domain.id
        )
        session.add(whitelist)
        session.commit()
        print(f"Added whitelisted IP: {ip_address} for domain {domain_name}")
        return True
    except Exception as e:
        session.rollback()
        print(f"Error adding whitelisted IP: {e}")
        return False
    finally:
        session.close()

def generate_dkim_key(domain_name):
    """Generate DKIM key for a domain."""
    dkim_manager = DKIMManager()
    if dkim_manager.generate_dkim_keypair(domain_name):
        print(f"Generated DKIM key for domain: {domain_name}")
        
        # Show DNS record
        dns_record = dkim_manager.get_dkim_public_key_record(domain_name)
        if dns_record:
            print("\nAdd this DNS TXT record:")
            print(f"Name: {dns_record['name']}")
            print(f"Value: {dns_record['value']}")
        return True
    else:
        print(f"Failed to generate DKIM key for domain: {domain_name}")
        return False

def list_dkim_keys():
    """List all DKIM keys."""
    dkim_manager = DKIMManager()
    keys = dkim_manager.list_dkim_keys()
    
    if not keys:
        print("No DKIM keys found")
        return
    
    print("DKIM Keys:")
    print("-" * 60)
    for key in keys:
        status = "ACTIVE" if key['active'] else "INACTIVE"
        print(f"Domain: {key['domain']}")
        print(f"Selector: {key['selector']}")
        print(f"Status: {status}")
        print(f"Created: {key['created_at']}")
        print("-" * 60)

def show_dns_records():
    """Show DNS records for all domains."""
    dkim_manager = DKIMManager()
    session = Session()
    try:
        domains = session.query(Domain).all()
        if not domains:
            print("No domains found")
            return
        
        print("DNS Records for DKIM:")
        print("=" * 80)
        
        for domain in domains:
            dns_record = dkim_manager.get_dkim_public_key_record(domain.domain_name)
            if dns_record:
                print(f"\nDomain: {domain.domain_name}")
                print(f"Record Name: {dns_record['name']}")
                print(f"Record Type: {dns_record['type']}")
                print(f"Record Value: {dns_record['value']}")
                print("-" * 80)
    finally:
        session.close()

def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(description="SMTP Server Management Tool")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Initialize command
    init_parser = subparsers.add_parser('init', help='Initialize database')
    
    # Domain commands
    domain_parser = subparsers.add_parser('add-domain', help='Add a domain')
    domain_parser.add_argument('domain', help='Domain name')
    domain_parser.add_argument('--no-auth', action='store_true', help='Domain does not require authentication')
    
    # User commands
    user_parser = subparsers.add_parser('add-user', help='Add a user')
    user_parser.add_argument('email', help='User email')
    user_parser.add_argument('password', help='User password')
    user_parser.add_argument('domain', help='Domain name')
    
    # IP whitelist commands
    ip_parser = subparsers.add_parser('add-ip', help='Add whitelisted IP')
    ip_parser.add_argument('ip', help='IP address')
    ip_parser.add_argument('domain', help='Domain name')
    
    # DKIM commands
    dkim_parser = subparsers.add_parser('generate-dkim', help='Generate DKIM key for domain')
    dkim_parser.add_argument('domain', help='Domain name')
    
    list_dkim_parser = subparsers.add_parser('list-dkim', help='List DKIM keys')
    
    dns_parser = subparsers.add_parser('show-dns', help='Show DNS records for DKIM')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == 'init':
        create_tables()
        print("Database tables created successfully")
    
    elif args.command == 'add-domain':
        add_domain(args.domain, not args.no_auth)
    
    elif args.command == 'add-user':
        add_user(args.email, args.password, args.domain)
    
    elif args.command == 'add-ip':
        add_whitelisted_ip(args.ip, args.domain)
    
    elif args.command == 'generate-dkim':
        generate_dkim_key(args.domain)
    
    elif args.command == 'list-dkim':
        list_dkim_keys()
    
    elif args.command == 'show-dns':
        show_dns_records()

if __name__ == '__main__':
    main()
