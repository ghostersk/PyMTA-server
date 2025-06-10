"""
DKIM blueprint for the SMTP server web UI.

This module provides DKIM key management functionality including:
- DKIM key listing
- DKIM key creation
- DKIM key regeneration
- DKIM key editing
- DKIM DNS verification
"""

from flask import render_template, request, redirect, url_for, flash, jsonify
from datetime import datetime
import re
from email_server.models import Session, Domain, DKIMKey
from email_server.dkim_manager import DKIMManager
from email_server.tool_box import get_logger
from .utils import get_public_ip, check_dns_record, generate_spf_record
from .routes import email_bp

logger = get_logger()


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
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'message': 'DKIM key not found'})
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
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': True,
                'message': f'DKIM key for {domain.domain_name} (selector: {dkim_key.selector}) has been {status_text}',
                'is_active': dkim_key.is_active
            })
        
        flash(f'DKIM key for {domain.domain_name} (selector: {dkim_key.selector}) has been {status_text}', 'success')
        return redirect(url_for('email.dkim_list'))
    except Exception as e:
        session.rollback()
        logger.error(f"Error toggling DKIM status: {e}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': f'Error toggling DKIM status: {str(e)}'})
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
    
    spf_valid_for_server = False
    spf_check_message = ''
    public_ip = get_public_ip()
    ip_mechanism = f'ip4:{public_ip}'
    if spf_record:
        result['spf_record'] = spf_record
        if ip_mechanism in spf_record:
            spf_valid_for_server = True
            spf_check_message = f'SPF is valid for this server (contains {ip_mechanism})'
        else:
            spf_check_message = f'SPF is missing this server\'s IP ({ip_mechanism})'
        result['message'] = 'SPF record found'
    else:
        result['success'] = False
        result['message'] = 'No SPF record found'
    result['spf_valid_for_server'] = spf_valid_for_server
    result['spf_check_message'] = spf_check_message
    result['public_ip'] = public_ip
    return jsonify(result)