"""
Domains blueprint for the SMTP server web UI.

This module provides domain management functionality including:
- Domain listing
- Domain creation
- Domain editing
- Domain deletion
- Domain status toggling
"""

from flask import render_template, request, redirect, url_for, flash
from email_server.models import Session, Domain, Sender, WhitelistedIP, DKIMKey, CustomHeader
from email_server.dkim_manager import DKIMManager
from email_server.tool_box import get_logger
from sqlalchemy.orm import joinedload
from .routes import email_bp


logger = get_logger()

@email_bp.route('/domains')
def domains_list():
    """List all domains."""
    session = Session()
    try:
        # Query domains - relationships will be loaded automatically due to lazy="joined"
        domains = session.query(Domain).order_by(Domain.domain_name).all()
        return render_template('domains.html', domains=domains)
    except Exception as e:
        logger.error(f"Error listing domains: {e}")
        flash('Error loading domains', 'error')
        return redirect(url_for('email.domains_list'))
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
        sender_count = session.query(Sender).filter_by(domain_id=domain_id).count()
        ip_count = session.query(WhitelistedIP).filter_by(domain_id=domain_id).count()
        dkim_count = session.query(DKIMKey).filter_by(domain_id=domain_id).count()
        
        # Delete associated records
        session.query(Sender).filter_by(domain_id=domain_id).delete()
        session.query(WhitelistedIP).filter_by(domain_id=domain_id).delete()
        session.query(DKIMKey).filter_by(domain_id=domain_id).delete()
        session.query(CustomHeader).filter_by(domain_id=domain_id).delete()
        
        # Delete domain
        session.delete(domain)
        session.commit()
        
        flash(f'Domain {domain_name} and all associated data permanently removed ({sender_count} senders, {ip_count} IPs, {dkim_count} DKIM keys)', 'success')
        return redirect(url_for('email.domains_list'))
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error removing domain: {e}")
        flash(f'Error removing domain: {str(e)}', 'error')
        return redirect(url_for('email.domains_list'))
    finally:
        session.close()