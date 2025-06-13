"""
IP Whitelist blueprint for the SMTP server web UI.

This module provides IP whitelist management functionality including:
- IP whitelist listing
- IP whitelist creation
- IP whitelist editing
- IP whitelist deletion
"""

from flask import render_template, request, redirect, url_for, flash
from email_server.models import Session, Domain, WhitelistedIP
from email_server.tool_box import get_logger
from .routes import email_bp
import socket

logger = get_logger()


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
            store_message_content = bool(request.form.get('store_message_content'))
            
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
                domain_id=domain_id,
                store_message_content=store_message_content
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
def disable_ip(ip_id: int):
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
            store_message_content = bool(request.form.get('store_message_content'))
            
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
            ip_record.store_message_content = store_message_content
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