"""
Flask Blueprint for Email Server Management Frontend

This module provides a comprehensive web interface for managing the SMTP server:
- Domain management
- User authentication and authorization
- DKIM key management with DNS record verification
- Server settings configuration
- Email logs and monitoring

Security features:
- Authentication management per domain
- IP whitelisting capabilities
- SPF and DKIM DNS validation
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
import socket
import requests
import dns.resolver
import re
from datetime import datetime
from datetime import datetime
from typing import Optional, Dict, List, Tuple

# Import email server modules
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from email_server.models import (
    Session, Domain, User, WhitelistedIP, DKIMKey, CustomHeader, EmailLog, AuthLog,
    hash_password, create_tables, get_user_by_email, get_domain_by_name, get_whitelisted_ip
)
from email_server.dkim_manager import DKIMManager
from email_server.settings_loader import load_settings, SETTINGS_PATH
from email_server.tool_box import get_logger

logger = get_logger()

# Create Blueprint
email_bp = Blueprint('email', __name__, 
                    template_folder='templates',
                    static_folder='static',
                    url_prefix='/pymta-manager')

def get_public_ip() -> str:
    """Get the public IP address of the server."""
    try:
        response1 = requests.get('https://ifconfig.me/ip', timeout=3, verify=False)

        ip = response1.text.strip()
        if ip and ip != 'unknown':
            return ip
    except Exception:
        try:
            # Fallback method
            response = requests.get('https://httpbin.org/ip', timeout=3, verify=False)
            ip = response.json()['origin'].split(',')[0].strip()
            if ip and ip != 'unknown':
                return ip
        except Exception as e:
            pass

    # Use fallback from settings.ini if available
    try:
        settings = load_settings()
        fallback_ip = settings.get('DKIM', 'SPF_SERVER_IP', fallback=None)
        if fallback_ip and fallback_ip.strip() and fallback_ip != '""':
            # Check if it's a valid IPv4 address (basic check)
            parts = fallback_ip.split('.')
            if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                return fallback_ip.strip()
    except Exception as e:
        return {'success': False, 'message': f'DNS lookup error, If it continues, consider setting up public IP in settings - SPF_SERVER_IP. Details: {str(e)}'}

def check_dns_record(domain: str, record_type: str, expected_value: str = None) -> Dict:
    """Check DNS record for a domain."""
    try:
        answers = dns.resolver.resolve(domain, record_type)
        records = [str(answer) for answer in answers]
        
        if expected_value:
            found = any(expected_value in record for record in records)
            return {
                'success': True,
                'found': found,
                'records': records,
                'message': f"Record {'found' if found else 'not found'}"
            }
        else:
            return {
                'success': True,
                'records': records,
                'message': f"Found {len(records)} {record_type} record(s)"
            }
    except dns.resolver.NXDOMAIN:
        return {'success': False, 'message': 'Domain not found'}
    except dns.resolver.NoAnswer:
        return {'success': False, 'message': f'No {record_type} records found'}
    except Exception as e:
        return {'success': False, 'message': f'DNS lookup error: {str(e)}'}

def generate_spf_record(domain: str, public_ip: str, existing_spf: str = None) -> str:
    """Generate or update SPF record to include the current server IP."""
    if not public_ip or public_ip == 'unknown':
        return f'"{existing_spf or "v=spf1 ~all"}"'

    our_ip = f"ip4:{public_ip}"

    if existing_spf:
        spf_clean = existing_spf.replace('"', '').strip()
        if not spf_clean.startswith('v=spf1'):
            spf_clean = f"v=spf1 {spf_clean}"

        parts = spf_clean.split()
        if our_ip in parts:
            return f'Current SPF records includes already server ip {public_ip}'

        # Find position of the final all mechanism (if present)
        all_mechanism_index = next((i for i, part in enumerate(parts) if part in ['-all', '~all', '?all', 'all']), None)
        
        if all_mechanism_index is not None:
            new_parts = parts[:all_mechanism_index] + [our_ip] + parts[all_mechanism_index:]
        else:
            new_parts = parts + [our_ip, '~all']
        
        return f'"{" ".join(new_parts)}"'
    else:
        # No existing SPF, create a new one
        return f'"v=spf1 {our_ip} ~all"'

# Dashboard and Main Routes
@email_bp.route('/')
def dashboard():
    """Main dashboard showing overview of the email server."""
    session = Session()
    try:
        # Get counts
        domain_count = session.query(Domain).filter_by(is_active=True).count()
        user_count = session.query(User).filter_by(is_active=True).count()
        dkim_count = session.query(DKIMKey).filter_by(is_active=True).count()
        
        # Get recent email logs
        recent_emails = session.query(EmailLog).order_by(EmailLog.created_at.desc()).limit(10).all()
        
        # Get recent auth logs
        recent_auths = session.query(AuthLog).order_by(AuthLog.created_at.desc()).limit(10).all()
        
        return render_template('dashboard.html',
                             domain_count=domain_count,
                             user_count=user_count,
                             dkim_count=dkim_count,
                             recent_emails=recent_emails,
                             recent_auths=recent_auths)
    finally:
        session.close()

# Domain Management Routes
@email_bp.route('/domains')
def domains_list():
    """List all domains."""
    session = Session()
    try:
        domains = session.query(Domain).order_by(Domain.domain_name).all()
        return render_template('domains.html', domains=domains)
    finally:
        session.close()

@email_bp.route('/domains/add', methods=['GET', 'POST'])
def add_domain():
    """Add new domain."""
    if request.method == 'POST':
        domain_name = request.form.get('domain_name', '').strip().lower()
        
        if not domain_name:
            flash('Domain name is required', 'error')
            return redirect(url_for('email.add_domain'))
        
        session = Session()
        try:
            # Check if domain already exists
            existing = session.query(Domain).filter_by(domain_name=domain_name).first()
            if existing:
                flash(f'Domain {domain_name} already exists', 'error')
                return redirect(url_for('email.domains_list'))
            
            # Create domain
            domain = Domain(domain_name=domain_name)
            session.add(domain)
            session.commit()
            
            # Generate DKIM key for the domain
            dkim_manager = DKIMManager()
            dkim_manager.generate_dkim_keypair(domain_name)
            
            flash(f'Domain {domain_name} added successfully with DKIM key', 'success')
            return redirect(url_for('email.domains_list'))
            
        except Exception as e:
            session.rollback()
            logger.error(f"Error adding domain: {e}")
            flash(f'Error adding domain: {str(e)}', 'error')
            return redirect(url_for('email.add_domain'))
        finally:
            session.close()
    
    return render_template('add_domain.html')

@email_bp.route('/domains/<int:domain_id>/delete', methods=['POST'])
def delete_domain(domain_id: int):
    """Delete domain (soft delete)."""
    session = Session()
    try:
        domain = session.query(Domain).get(domain_id)
        if not domain:
            flash('Domain not found', 'error')
            return redirect(url_for('email.domains_list'))
        
        domain_name = domain.domain_name
        domain.is_active = False
        session.commit()
        
        flash(f'Domain {domain_name} disabled', 'success')
        return redirect(url_for('email.domains_list'))
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error disabling domain: {e}")
        flash(f'Error disabling domain: {str(e)}', 'error')
        return redirect(url_for('email.domains_list'))
    finally:
        session.close()

@email_bp.route('/domains/<int:domain_id>/edit', methods=['GET', 'POST'])
def edit_domain(domain_id: int):
    """Edit domain."""
    session = Session()
    try:
        domain = session.query(Domain).get(domain_id)
        if not domain:
            flash('Domain not found', 'error')
            return redirect(url_for('email.domains_list'))
        
        if request.method == 'POST':
            domain_name = request.form.get('domain_name', '').strip().lower()
            requires_auth = request.form.get('requires_auth') == 'on'
            
            if not domain_name:
                flash('Domain name is required', 'error')
                return redirect(url_for('email.edit_domain', domain_id=domain_id))
            
            # Basic domain validation
            if '.' not in domain_name or len(domain_name.split('.')) < 2:
                flash('Invalid domain format', 'error')
                return redirect(url_for('email.edit_domain', domain_id=domain_id))
            
            # Check if domain name already exists (excluding current domain)
            existing = session.query(Domain).filter(
                Domain.domain_name == domain_name,
                Domain.id != domain_id
            ).first()
            if existing:
                flash(f'Domain {domain_name} already exists', 'error')
                return redirect(url_for('email.edit_domain', domain_id=domain_id))
            
            old_name = domain.domain_name
            domain.domain_name = domain_name
            domain.requires_auth = requires_auth
            session.commit()
            
            flash(f'Domain updated from "{old_name}" to "{domain_name}"', 'success')
            return redirect(url_for('email.domains_list'))
        
        return render_template('edit_domain.html', domain=domain)
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error editing domain: {e}")
        flash(f'Error editing domain: {str(e)}', 'error')
        return redirect(url_for('email.domains_list'))
    finally:
        session.close()

@email_bp.route('/domains/<int:domain_id>/toggle', methods=['POST'])
def toggle_domain(domain_id: int):
    """Toggle domain active status (Enable/Disable)."""
    session = Session()
    try:
        domain = session.query(Domain).get(domain_id)
        if not domain:
            flash('Domain not found', 'error')
            return redirect(url_for('email.domains_list'))
        
        old_status = domain.is_active
        domain.is_active = not old_status
        session.commit()
        
        status_text = "enabled" if domain.is_active else "disabled"
        flash(f'Domain {domain.domain_name} has been {status_text}', 'success')
        return redirect(url_for('email.domains_list'))
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error toggling domain status: {e}")
        flash(f'Error toggling domain status: {str(e)}', 'error')
        return redirect(url_for('email.domains_list'))
    finally:
        session.close()

@email_bp.route('/domains/<int:domain_id>/remove', methods=['POST'])
def remove_domain(domain_id: int):
    """Permanently remove domain and all associated data."""
    session = Session()
    try:
        domain = session.query(Domain).get(domain_id)
        if not domain:
            flash('Domain not found', 'error')
            return redirect(url_for('email.domains_list'))
        
        domain_name = domain.domain_name
        
        # Count associated records
        user_count = session.query(User).filter_by(domain_id=domain_id).count()
        ip_count = session.query(WhitelistedIP).filter_by(domain_id=domain_id).count()
        dkim_count = session.query(DKIMKey).filter_by(domain_id=domain_id).count()
        
        # Delete associated records
        session.query(User).filter_by(domain_id=domain_id).delete()
        session.query(WhitelistedIP).filter_by(domain_id=domain_id).delete()
        session.query(DKIMKey).filter_by(domain_id=domain_id).delete()
        session.query(CustomHeader).filter_by(domain_id=domain_id).delete()
        
        # Delete domain
        session.delete(domain)
        session.commit()
        
        flash(f'Domain {domain_name} and all associated data permanently removed ({user_count} users, {ip_count} IPs, {dkim_count} DKIM keys)', 'success')
        return redirect(url_for('email.domains_list'))
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error removing domain: {e}")
        flash(f'Error removing domain: {str(e)}', 'error')
        return redirect(url_for('email.domains_list'))
    finally:
        session.close()

# User Management Routes
@email_bp.route('/users')
def users_list():
    """List all users."""
    session = Session()
    try:
        users = session.query(User, Domain).join(Domain, User.domain_id == Domain.id).order_by(User.email).all()
        return render_template('users.html', users=users)
    finally:
        session.close()

@email_bp.route('/users/add', methods=['GET', 'POST'])
def add_user():
    """Add new user."""
    session = Session()
    try:
        domains = session.query(Domain).filter_by(is_active=True).order_by(Domain.domain_name).all()
        
        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '').strip()
            domain_id = request.form.get('domain_id', type=int)
            can_send_as_domain = request.form.get('can_send_as_domain') == 'on'
            
            if not all([email, password, domain_id]):
                flash('All fields are required', 'error')
                return redirect(url_for('email.add_user'))
            
            # Validate email format
            if '@' not in email:
                flash('Invalid email format', 'error')
                return redirect(url_for('email.add_user'))
            
            # Check if user already exists
            existing = session.query(User).filter_by(email=email).first()
            if existing:
                flash(f'User {email} already exists', 'error')
                return redirect(url_for('email.users_list'))
            
            # Create user
            user = User(
                email=email,
                password_hash=hash_password(password),
                domain_id=domain_id,
                can_send_as_domain=can_send_as_domain
            )
            session.add(user)
            session.commit()
            
            flash(f'User {email} added successfully', 'success')
            return redirect(url_for('email.users_list'))
        
        return render_template('add_user.html', domains=domains)
    
    except Exception as e:
        session.rollback()
        logger.error(f"Error adding user: {e}")
        flash(f'Error adding user: {str(e)}', 'error')
        return redirect(url_for('email.add_user'))
    finally:
        session.close()

@email_bp.route('/users/<int:user_id>/delete', methods=['POST'])
def delete_user(user_id: int):
    """Disable user (soft delete)."""
    session = Session()
    try:
        user = session.query(User).get(user_id)
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('email.users_list'))
        
        user_email = user.email
        user.is_active = False
        session.commit()
        
        flash(f'User {user_email} disabled', 'success')
        return redirect(url_for('email.users_list'))
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error disabling user: {e}")
        flash(f'Error disabling user: {str(e)}', 'error')
        return redirect(url_for('email.users_list'))
    finally:
        session.close()

@email_bp.route('/users/<int:user_id>/enable', methods=['POST'])
def enable_user(user_id: int):
    """Enable user."""
    session = Session()
    try:
        user = session.query(User).get(user_id)
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('email.users_list'))
        
        user_email = user.email
        user.is_active = True
        session.commit()
        
        flash(f'User {user_email} enabled', 'success')
        return redirect(url_for('email.users_list'))
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error enabling user: {e}")
        flash(f'Error enabling user: {str(e)}', 'error')
        return redirect(url_for('email.users_list'))
    finally:
        session.close()

@email_bp.route('/users/<int:user_id>/remove', methods=['POST'])
def remove_user(user_id: int):
    """Permanently remove user."""
    session = Session()
    try:
        user = session.query(User).get(user_id)
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('email.users_list'))
        
        user_email = user.email
        session.delete(user)
        session.commit()
        
        flash(f'User {user_email} permanently removed', 'success')
        return redirect(url_for('email.users_list'))
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error removing user: {e}")
        flash(f'Error removing user: {str(e)}', 'error')
        return redirect(url_for('email.users_list'))
    finally:
        session.close()

@email_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
def edit_user(user_id: int):
    """Edit user."""
    session = Session()
    try:
        user = session.query(User).get(user_id)
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('email.users_list'))
        
        domains = session.query(Domain).filter_by(is_active=True).order_by(Domain.domain_name).all()
        
        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '').strip()
            domain_id = request.form.get('domain_id', type=int)
            can_send_as_domain = request.form.get('can_send_as_domain') == 'on'
            
            if not all([email, domain_id]):
                flash('Email and domain are required', 'error')
                return redirect(url_for('email.edit_user', user_id=user_id))
            
            # Email validation
            if '@' not in email or '.' not in email.split('@')[1]:
                flash('Invalid email format', 'error')
                return redirect(url_for('email.edit_user', user_id=user_id))
            
            # Check if email already exists (excluding current user)
            existing = session.query(User).filter(
                User.email == email,
                User.id != user_id
            ).first()
            if existing:
                flash(f'Email {email} already exists', 'error')
                return redirect(url_for('email.edit_user', user_id=user_id))
            
            # Update user
            user.email = email
            user.domain_id = domain_id
            user.can_send_as_domain = can_send_as_domain
            
            # Update password if provided
            if password:
                user.password_hash = hash_password(password)
            
            session.commit()
            
            flash(f'User {email} updated successfully', 'success')
            return redirect(url_for('email.users_list'))
        
        return render_template('edit_user.html', user=user, domains=domains)
    
    except Exception as e:
        session.rollback()
        logger.error(f"Error editing user: {e}")
        flash(f'Error editing user: {str(e)}', 'error')
        return redirect(url_for('email.users_list'))
    finally:
        session.close()

# IP Management Routes
@email_bp.route('/ips')
def ips_list():
    """List all whitelisted IPs."""
    session = Session()
    try:
        ips = session.query(WhitelistedIP, Domain).join(Domain, WhitelistedIP.domain_id == Domain.id).order_by(WhitelistedIP.ip_address).all()
        return render_template('ips.html', ips=ips)
    finally:
        session.close()

@email_bp.route('/ips/add', methods=['GET', 'POST'])
def add_ip():
    """Add new whitelisted IP."""
    session = Session()
    try:
        domains = session.query(Domain).filter_by(is_active=True).order_by(Domain.domain_name).all()
        
        if request.method == 'POST':
            ip_address = request.form.get('ip_address', '').strip()
            domain_id = request.form.get('domain_id', type=int)
            
            if not all([ip_address, domain_id]):
                flash('All fields are required', 'error')
                return redirect(url_for('email.add_ip'))
            
            # Basic IP validation
            try:
                socket.inet_aton(ip_address)
            except socket.error:
                flash('Invalid IP address format', 'error')
                return redirect(url_for('email.add_ip'))
            
            # Check if IP already exists for this domain
            existing = session.query(WhitelistedIP).filter_by(ip_address=ip_address, domain_id=domain_id).first()
            if existing:
                flash(f'IP {ip_address} already whitelisted for this domain', 'error')
                return redirect(url_for('email.ips_list'))
            
            # Create whitelisted IP
            whitelist = WhitelistedIP(
                ip_address=ip_address,
                domain_id=domain_id
            )
            session.add(whitelist)
            session.commit()
            
            flash(f'IP {ip_address} added to whitelist', 'success')
            return redirect(url_for('email.ips_list'))
        
        return render_template('add_ip.html', domains=domains)
    
    except Exception as e:
        session.rollback()
        logger.error(f"Error adding IP: {e}")
        flash(f'Error adding IP: {str(e)}', 'error')
        return redirect(url_for('email.add_ip'))
    finally:
        session.close()

@email_bp.route('/ips/<int:ip_id>/delete', methods=['POST'])
def delete_ip(ip_id: int):
    """Disable whitelisted IP (soft delete)."""
    session = Session()
    try:
        ip_record = session.query(WhitelistedIP).get(ip_id)
        if not ip_record:
            flash('IP record not found', 'error')
            return redirect(url_for('email.ips_list'))
        
        ip_address = ip_record.ip_address
        ip_record.is_active = False
        session.commit()
        
        flash(f'IP {ip_address} disabled', 'success')
        return redirect(url_for('email.ips_list'))
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error disabling IP: {e}")
        flash(f'Error disabling IP: {str(e)}', 'error')
        return redirect(url_for('email.ips_list'))
    finally:
        session.close()

@email_bp.route('/ips/<int:ip_id>/enable', methods=['POST'])
def enable_ip(ip_id: int):
    """Enable whitelisted IP."""
    session = Session()
    try:
        ip_record = session.query(WhitelistedIP).get(ip_id)
        if not ip_record:
            flash('IP record not found', 'error')
            return redirect(url_for('email.ips_list'))
        
        ip_address = ip_record.ip_address
        ip_record.is_active = True
        session.commit()
        
        flash(f'IP {ip_address} enabled', 'success')
        return redirect(url_for('email.ips_list'))
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error enabling IP: {e}")
        flash(f'Error enabling IP: {str(e)}', 'error')
        return redirect(url_for('email.ips_list'))
    finally:
        session.close()

@email_bp.route('/ips/<int:ip_id>/remove', methods=['POST'])
def remove_ip(ip_id: int):
    """Permanently remove whitelisted IP."""
    session = Session()
    try:
        ip_record = session.query(WhitelistedIP).get(ip_id)
        if not ip_record:
            flash('IP record not found', 'error')
            return redirect(url_for('email.ips_list'))
        
        ip_address = ip_record.ip_address
        session.delete(ip_record)
        session.commit()
        
        flash(f'IP {ip_address} permanently removed', 'success')
        return redirect(url_for('email.ips_list'))
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error removing IP: {e}")
        flash(f'Error removing IP: {str(e)}', 'error')
        return redirect(url_for('email.ips_list'))
    finally:
        session.close()

@email_bp.route('/ips/<int:ip_id>/edit', methods=['GET', 'POST'])
def edit_ip(ip_id: int):
    """Edit whitelisted IP."""
    session = Session()
    try:
        ip_record = session.query(WhitelistedIP).get(ip_id)
        if not ip_record:
            flash('IP record not found', 'error')
            return redirect(url_for('email.ips_list'))
        
        domains = session.query(Domain).filter_by(is_active=True).order_by(Domain.domain_name).all()
        
        if request.method == 'POST':
            ip_address = request.form.get('ip_address', '').strip()
            domain_id = request.form.get('domain_id', type=int)
            
            if not all([ip_address, domain_id]):
                flash('All fields are required', 'error')
                return redirect(url_for('email.edit_ip', ip_id=ip_id))
            
            # Basic IP validation
            try:
                socket.inet_aton(ip_address)
            except socket.error:
                flash('Invalid IP address format', 'error')
                return redirect(url_for('email.edit_ip', ip_id=ip_id))
            
            # Check if IP already exists for this domain (excluding current record)
            existing = session.query(WhitelistedIP).filter(
                WhitelistedIP.ip_address == ip_address,
                WhitelistedIP.domain_id == domain_id,
                WhitelistedIP.id != ip_id
            ).first()
            if existing:
                flash(f'IP {ip_address} already whitelisted for this domain', 'error')
                return redirect(url_for('email.edit_ip', ip_id=ip_id))
            
            # Update IP record
            ip_record.ip_address = ip_address
            ip_record.domain_id = domain_id
            session.commit()
            
            flash(f'IP whitelist record updated', 'success')
            return redirect(url_for('email.ips_list'))
        
        return render_template('edit_ip.html', ip_record=ip_record, domains=domains)
    
    except Exception as e:
        session.rollback()
        logger.error(f"Error editing IP: {e}")
        flash(f'Error editing IP: {str(e)}', 'error')
        return redirect(url_for('email.ips_list'))
    finally:
        session.close()

# DKIM Management Routes
@email_bp.route('/dkim')
def dkim_list():
    """List all DKIM keys and DNS records."""
    session = Session()
    try:
        # Get active DKIM keys
        active_dkim_keys = session.query(DKIMKey, Domain).join(
            Domain, DKIMKey.domain_id == Domain.id
        ).filter(DKIMKey.is_active == True).order_by(Domain.domain_name).all()
        
        # Get old/inactive DKIM keys (prioritize replaced keys over disabled ones)
        old_dkim_keys = session.query(DKIMKey, Domain).join(
            Domain, DKIMKey.domain_id == Domain.id
        ).filter(DKIMKey.is_active == False).order_by(
            Domain.domain_name, 
            DKIMKey.replaced_at.desc().nullslast(),  # Replaced keys first, then disabled ones
            DKIMKey.created_at.desc()
        ).all()
        
        # Get public IP for SPF records
        public_ip = get_public_ip()
        
        # Prepare active DKIM data with DNS information
        active_dkim_data = []
        for dkim_key, domain in active_dkim_keys:
            # Get DKIM DNS record
            dkim_manager = DKIMManager()
            dns_record = dkim_manager.get_dkim_public_key_record(domain.domain_name)
            
            # Check existing SPF record
            spf_check = check_dns_record(domain.domain_name, 'TXT')
            existing_spf = None
            if spf_check['success']:
                for record in spf_check['records']:
                    if 'v=spf1' in record:
                        existing_spf = record
                        break
            
            # Generate recommended SPF
            recommended_spf = generate_spf_record(domain.domain_name, public_ip, existing_spf)
            
            active_dkim_data.append({
                'dkim_key': dkim_key,
                'domain': domain,
                'dns_record': dns_record,
                'existing_spf': existing_spf,
                'recommended_spf': recommended_spf,
                'public_ip': public_ip
            })
        
        # Prepare old DKIM data with status information
        old_dkim_data = []
        for dkim_key, domain in old_dkim_keys:
            old_dkim_data.append({
                'dkim_key': dkim_key,
                'domain': domain,
                'public_ip': public_ip,
                'is_replaced': dkim_key.replaced_at is not None,
                'status_text': 'Replaced' if dkim_key.replaced_at else 'Disabled'
            })
        
        return render_template('dkim.html', 
                             dkim_data=active_dkim_data, 
                             old_dkim_data=old_dkim_data)
    finally:
        session.close()

@email_bp.route('/dkim/<int:domain_id>/regenerate', methods=['POST'])
def regenerate_dkim(domain_id: int):
    """Regenerate DKIM key for domain."""
    session = Session()
    try:
        domain = session.query(Domain).get(domain_id)
        if not domain:
            if request.headers.get('Content-Type') == 'application/json':
                return jsonify({'success': False, 'message': 'Domain not found'})
            flash('Domain not found', 'error')
            return redirect(url_for('email.dkim_list'))
        
        # Get the current active DKIM key's selector to preserve it
        existing_keys = session.query(DKIMKey).filter_by(domain_id=domain_id, is_active=True).all()
        current_selector = None
        if existing_keys:
            # Use the selector from the first active key (there should typically be only one)
            current_selector = existing_keys[0].selector
        
        # Mark existing keys as replaced
        for key in existing_keys:
            key.is_active = False
            key.replaced_at = datetime.now()  # Mark when this key was replaced
        
        # Generate new DKIM key preserving the existing selector
        dkim_manager = DKIMManager()
        if dkim_manager.generate_dkim_keypair(domain.domain_name, selector=current_selector, force_new_key=True):
            session.commit()
            
            # Get the new key data for AJAX response
            new_key = session.query(DKIMKey).filter_by(
                domain_id=domain_id, is_active=True
            ).order_by(DKIMKey.created_at.desc()).first()
            
            if not new_key:
                session.rollback()
                if request.headers.get('Content-Type') == 'application/json' or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'success': False, 'message': f'Failed to create new DKIM key for {domain.domain_name}'})
                flash(f'Failed to create new DKIM key for {domain.domain_name}', 'error')
                return redirect(url_for('email.dkim_list'))
            
            if request.headers.get('Content-Type') == 'application/json' or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                # Get updated DNS record for the new key
                dns_record = dkim_manager.get_dkim_public_key_record(domain.domain_name)
                public_ip = get_public_ip()
                
                # Check existing SPF record
                spf_check = check_dns_record(domain.domain_name, 'TXT')
                existing_spf = None
                if spf_check['success']:
                    for record in spf_check['records']:
                        if 'v=spf1' in record:
                            existing_spf = record
                            break
                
                recommended_spf = generate_spf_record(domain.domain_name, public_ip, existing_spf)
                
                # Get replaced keys for the Old DKIM section update
                old_keys = session.query(DKIMKey, Domain).join(
                    Domain, DKIMKey.domain_id == Domain.id
                ).filter(
                    DKIMKey.domain_id == domain_id,
                    DKIMKey.is_active == False
                ).order_by(DKIMKey.created_at.desc()).all()
                
                old_dkim_data = []
                for old_key, old_domain in old_keys:
                    status_text = "Replaced" if old_key.replaced_at else "Disabled"
                    old_dkim_data.append({
                        'dkim_key': {
                            'id': old_key.id,
                            'selector': old_key.selector,
                            'created_at': old_key.created_at.strftime('%Y-%m-%d %H:%M'),
                            'replaced_at': old_key.replaced_at.strftime('%Y-%m-%d %H:%M') if old_key.replaced_at else None,
                            'is_active': old_key.is_active
                        },
                        'domain': {
                            'id': old_domain.id,
                            'domain_name': old_domain.domain_name
                        },
                        'status_text': status_text,
                        'public_ip': public_ip
                    })
                
                # Additional null check for new_key before accessing its attributes
                if not new_key:
                    logger.error(f"new_key is None after generation for domain {domain.domain_name}")
                    return jsonify({'success': False, 'message': f'Failed to retrieve new DKIM key for {domain.domain_name}'})
                
                return jsonify({
                    'success': True,
                    'message': f'DKIM key regenerated for {domain.domain_name}',
                    'new_key': {
                        'id': new_key.id,
                        'selector': new_key.selector,
                        'created_at': new_key.created_at.strftime('%Y-%m-%d %H:%M'),
                        'is_active': new_key.is_active
                    },
                    'dns_record': {
                        'name': dns_record['name'] if dns_record else '',
                        'value': dns_record['value'] if dns_record else ''
                    },
                    'existing_spf': existing_spf,
                    'recommended_spf': recommended_spf,
                    'public_ip': public_ip,
                    'domain': {
                        'id': domain.id,
                        'domain_name': domain.domain_name
                    },
                    'old_dkim_data': old_dkim_data
                })
            
            flash(f'DKIM key regenerated for {domain.domain_name}', 'success')
        else:
            session.rollback()
            if request.headers.get('Content-Type') == 'application/json' or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'message': f'Failed to regenerate DKIM key for {domain.domain_name}'})
            flash(f'Failed to regenerate DKIM key for {domain.domain_name}', 'error')
        
        return redirect(url_for('email.dkim_list'))
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error regenerating DKIM: {e}")
        if request.headers.get('Content-Type') == 'application/json' or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': f'Error regenerating DKIM: {str(e)}'})
        flash(f'Error regenerating DKIM: {str(e)}', 'error')
        return redirect(url_for('email.dkim_list'))
    finally:
        session.close()

@email_bp.route('/dkim/<int:dkim_id>/edit', methods=['GET', 'POST'])
def edit_dkim(dkim_id: int):
    """Edit DKIM key selector."""
    session = Session()
    try:
        dkim_key = session.query(DKIMKey).get(dkim_id)
        if not dkim_key:
            flash('DKIM key not found', 'error')
            return redirect(url_for('email.dkim_list'))
        
        domain = session.query(Domain).get(dkim_key.domain_id)
        
        if request.method == 'POST':
            new_selector = request.form.get('selector', '').strip()
            
            if not new_selector:
                flash('Selector name is required', 'error')
                return render_template('edit_dkim.html', dkim_key=dkim_key, domain=domain)
            
            # Validate selector (alphanumeric only)
            if not re.match(r'^[a-zA-Z0-9_-]+$', new_selector):
                flash('Selector must contain only letters, numbers, hyphens, and underscores', 'error')
                return render_template('edit_dkim.html', dkim_key=dkim_key, domain=domain)
            
            # Check for duplicate selector in same domain
            existing = session.query(DKIMKey).filter_by(
                domain_id=dkim_key.domain_id, 
                selector=new_selector,
                is_active=True
            ).filter(DKIMKey.id != dkim_id).first()
            
            if existing:
                flash(f'A DKIM key with selector "{new_selector}" already exists for this domain', 'error')
                return render_template('edit_dkim.html', dkim_key=dkim_key, domain=domain)
            
            old_selector = dkim_key.selector
            dkim_key.selector = new_selector
            session.commit()
            
            flash(f'DKIM selector updated from "{old_selector}" to "{new_selector}" for {domain.domain_name}', 'success')
            return redirect(url_for('email.dkim_list'))
        
        return render_template('edit_dkim.html', dkim_key=dkim_key, domain=domain)
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error editing DKIM: {e}")
        flash(f'Error editing DKIM key: {str(e)}', 'error')
        return redirect(url_for('email.dkim_list'))
    finally:
        session.close()

@email_bp.route('/dkim/<int:dkim_id>/toggle', methods=['POST'])
def toggle_dkim(dkim_id: int):
    """Toggle DKIM key active status (Enable/Disable)."""
    session = Session()
    try:
        dkim_key = session.query(DKIMKey).get(dkim_id)
        if not dkim_key:
            flash('DKIM key not found', 'error')
            return redirect(url_for('email.dkim_list'))
        domain = session.query(Domain).get(dkim_key.domain_id)
        old_status = dkim_key.is_active
        if not old_status:
            # About to activate this key, so deactivate any other active DKIM for this domain
            other_active_keys = session.query(DKIMKey).filter(
                DKIMKey.domain_id == dkim_key.domain_id,
                DKIMKey.is_active == True,
                DKIMKey.id != dkim_id
            ).all()
            for key in other_active_keys:
                key.is_active = False
                key.replaced_at = datetime.now()
        dkim_key.is_active = not old_status
        if dkim_key.is_active:
            dkim_key.replaced_at = None
        session.commit()
        status_text = "enabled" if dkim_key.is_active else "disabled"
        flash(f'DKIM key for {domain.domain_name} (selector: {dkim_key.selector}) has been {status_text}', 'success')
        return redirect(url_for('email.dkim_list'))
    except Exception as e:
        session.rollback()
        logger.error(f"Error toggling DKIM status: {e}")
        flash(f'Error toggling DKIM status: {str(e)}', 'error')
        return redirect(url_for('email.dkim_list'))
    finally:
        session.close()

@email_bp.route('/dkim/<int:dkim_id>/remove', methods=['POST'])
def remove_dkim(dkim_id: int):
    """Permanently remove DKIM key."""
    session = Session()
    try:
        dkim_key = session.query(DKIMKey).get(dkim_id)
        if not dkim_key:
            flash('DKIM key not found', 'error')
            return redirect(url_for('email.dkim_list'))
        
        domain = session.query(Domain).get(dkim_key.domain_id)
        selector = dkim_key.selector
        
        session.delete(dkim_key)
        session.commit()
        
        flash(f'DKIM key for {domain.domain_name} (selector: {selector}) has been permanently removed', 'success')
        return redirect(url_for('email.dkim_list'))
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error removing DKIM key: {e}")
        flash(f'Error removing DKIM key: {str(e)}', 'error')
        return redirect(url_for('email.dkim_list'))
    finally:
        session.close()

# AJAX DNS Check Routes
@email_bp.route('/dkim/check_dns', methods=['POST'])
def check_dkim_dns():
    """Check DKIM DNS record via AJAX."""
    domain = request.form.get('domain')
    selector = request.form.get('selector')
    
    if not all([domain, selector]):
        return jsonify({'success': False, 'message': 'Missing domain or selector parameters'})
    
    # Get the expected DKIM value from the DKIM manager
    try:
        dkim_manager = DKIMManager()
        dns_record = dkim_manager.get_dkim_public_key_record(domain)
        
        if not dns_record or not dns_record.get('value'):
            return jsonify({'success': False, 'message': 'No DKIM key found for domain'})
        
        expected_value = dns_record['value']
        
        dns_name = f"{selector}._domainkey.{domain}"
        result = check_dns_record(dns_name, 'TXT', expected_value)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error checking DKIM DNS: {e}")
        return jsonify({'success': False, 'message': f'Error checking DKIM DNS: {str(e)}'})

@email_bp.route('/dkim/check_spf', methods=['POST'])
def check_spf_dns():
    """Check SPF DNS record via AJAX."""
    domain = request.form.get('domain')
    
    if not domain:
        return jsonify({'success': False, 'message': 'Domain is required'})
    
    result = check_dns_record(domain, 'TXT')
    
    # Look for SPF record
    spf_record = None
    if result['success']:
        for record in result['records']:
            if 'v=spf1' in record:
                spf_record = record
                break
    
    if spf_record:
        result['spf_record'] = spf_record
        result['message'] = 'SPF record found'
    else:
        result['success'] = False
        result['message'] = 'No SPF record found'
    
    return jsonify(result)

# Settings Routes
@email_bp.route('/settings')
def settings():
    """Display and edit server settings."""
    settings = load_settings()
    return render_template('settings.html', settings=settings)

@email_bp.route('/settings/update', methods=['POST'])
def update_settings():
    """Update server settings."""
    try:
        # Load current settings
        config = load_settings()
        
        # Update settings from form
        for section_name in config.sections():
            for key in config[section_name]:
                if not key.startswith(';'):  # Skip comment lines
                    form_key = f"{section_name}.{key}"
                    if form_key in request.form:
                        config.set(section_name, key, request.form[form_key])
        
        # Save settings
        with open(SETTINGS_PATH, 'w') as f:
            config.write(f)
        
        flash('Settings updated successfully. Restart the server to apply changes.', 'success')
        return redirect(url_for('email.settings'))
        
    except Exception as e:
        logger.error(f"Error updating settings: {e}")
        flash(f'Error updating settings: {str(e)}', 'error')
        return redirect(url_for('email.settings'))

# Logs Routes
@email_bp.route('/logs')
def logs():
    """Display email and authentication logs."""
    session = Session()
    try:
        # Get filter parameters
        filter_type = request.args.get('type', 'all')
        page = request.args.get('page', 1, type=int)
        per_page = 50
        
        if filter_type == 'emails':
            # Email logs only
            total_query = session.query(EmailLog)
            logs_query = session.query(EmailLog).order_by(EmailLog.created_at.desc())
        elif filter_type == 'auth':
            # Auth logs only
            total_query = session.query(AuthLog)
            logs_query = session.query(AuthLog).order_by(AuthLog.created_at.desc())
        else:
            # Combined view (default)
            email_logs = session.query(EmailLog).order_by(EmailLog.created_at.desc()).limit(per_page//2).all()
            auth_logs = session.query(AuthLog).order_by(AuthLog.created_at.desc()).limit(per_page//2).all()
            
            # Convert to unified format
            combined_logs = []
            for log in email_logs:
                combined_logs.append({
                    'type': 'email',
                    'timestamp': log.created_at,
                    'data': log
                })
            for log in auth_logs:
                combined_logs.append({
                    'type': 'auth',
                    'timestamp': log.created_at,
                    'data': log
                })
            
            # Sort by timestamp
            combined_logs.sort(key=lambda x: x['timestamp'], reverse=True)
            
            return render_template('logs.html', 
                                 logs=combined_logs[:per_page], 
                                 filter_type=filter_type,
                                 page=page,
                                 has_next=len(combined_logs) > per_page,
                                 has_prev=page > 1)
        
        # Pagination for single type logs
        offset = (page - 1) * per_page
        total = total_query.count()
        logs = logs_query.offset(offset).limit(per_page).all()
        
        has_next = offset + per_page < total
        has_prev = page > 1
        
        return render_template('logs.html', 
                             logs=logs, 
                             filter_type=filter_type,
                             page=page,
                             has_next=has_next,
                             has_prev=has_prev)
    finally:
        session.close()

# Error handlers
@email_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return render_template('error.html', 
                         error_code=404,
                         error_message='Page not found',
                         current_time=datetime.now()), 404

@email_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal error: {error}")
    return render_template('error.html',
                         error_code=500,
                         error_message='Internal server error',
                         current_time=datetime.now()), 500

@email_bp.route('/dkim/create', methods=['POST'], endpoint='create_dkim')
def create_dkim():
    """Create a new DKIM key for a domain, optionally with a custom selector."""
    from flask import request, jsonify
    data = request.get_json() if request.is_json else request.form
    domain_name = data.get('domain')
    selector = data.get('selector', None)
    session = Session()
    try:
        if not domain_name:
            return jsonify({'success': False, 'message': 'Domain is required.'}), 400
        domain = session.query(Domain).filter_by(domain_name=domain_name).first()
        if not domain:
            return jsonify({'success': False, 'message': 'Domain not found.'}), 404
        # Deactivate any existing active DKIM key for this domain
        active_keys = session.query(DKIMKey).filter_by(domain_id=domain.id, is_active=True).all()
        for key in active_keys:
            key.is_active = False
            key.replaced_at = datetime.now()
        # Create new DKIM key
        dkim_manager = DKIMManager()
        created = dkim_manager.generate_dkim_keypair(domain_name, selector=selector, force_new_key=True)
        if created:
            session.commit()
            return jsonify({'success': True, 'message': f'DKIM key created for {domain_name}.'})
        else:
            session.rollback()
            return jsonify({'success': False, 'message': f'Failed to create DKIM key for {domain_name}.'}), 500
    except Exception as e:
        session.rollback()
        logger.error(f"Error creating DKIM: {e}")
        return jsonify({'success': False, 'message': f'Error creating DKIM: {str(e)}'}), 500
    finally:
        session.close()
