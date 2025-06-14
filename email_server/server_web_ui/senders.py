"""
Senders blueprint for the SMTP server web UI.

This module provides sender management functionality including:
- Sender listing
- Sender creation
- Sender editing
- Sender deletion
- Sender status toggling
"""

from flask import render_template, request, redirect, url_for, flash
from email_server.models import Session, Domain, Sender
from email_server.tool_box import get_logger
import bcrypt
from .routes import email_bp
from email_server.models import Session, Domain, Sender, hash_password

logger = get_logger()

@email_bp.route('/senders')
def senders_list():
    """List all senders."""
    session = Session()
    try:
        senders = session.query(Sender, Domain).join(Domain, Sender.domain_id == Domain.id).order_by(Sender.email).all()
        return render_template('senders.html', senders=senders)
    finally:
        session.close()

@email_bp.route('/senders/add', methods=['GET', 'POST'])
def add_sender():
    """Add new sender."""
    session = Session()
    try:
        domains = session.query(Domain).filter_by(is_active=True).order_by(Domain.domain_name).all()
        
        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '').strip()
            domain_id = request.form.get('domain_id', type=int)
            can_send_as_domain = request.form.get('can_send_as_domain') == 'on'
            store_message_content = request.form.get('store_message_content') == 'on'
            
            if not all([email, password, domain_id]):
                flash('All fields are required', 'error')
                return redirect(url_for('email.add_sender'))
            
            # Validate email format
            if '@' not in email:
                flash('Invalid email format', 'error')
                return redirect(url_for('email.add_sender'))
            
            # Check if sender already exists
            existing = session.query(Sender).filter_by(email=email).first()
            if existing:
                flash(f'Sender {email} already exists', 'error')
                return redirect(url_for('email.senders_list'))
            
            # Create sender
            sender = Sender(
                email=email,
                password_hash=hash_password(password),
                domain_id=domain_id,
                can_send_as_domain=can_send_as_domain,
                store_message_content=store_message_content
            )
            session.add(sender)
            session.commit()
            
            flash(f'Sender {email} added successfully', 'success')
            return redirect(url_for('email.senders_list'))
        
        return render_template('add_sender.html', domains=domains)
    
    except Exception as e:
        session.rollback()
        logger.error(f"Error adding sender: {e}")
        flash(f'Error adding sender: {str(e)}', 'error')
        return redirect(url_for('email.add_sender'))
    finally:
        session.close()

@email_bp.route('/senders/<int:user_id>/delete', methods=['POST'])
def delete_sender(user_id: int):
    """Disable sender (soft delete)."""
    session = Session()
    try:
        sender = session.query(Sender).get(user_id)
        if not sender:
            flash('Sender not found', 'error')
            return redirect(url_for('email.senders_list'))
        
        sender_email = sender.email
        sender.is_active = False
        session.commit()
        
        flash(f'Sender {sender_email} disabled', 'success')
        return redirect(url_for('email.senders_list'))
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error disabling sender: {e}")
        flash(f'Error disabling sender: {str(e)}', 'error')
        return redirect(url_for('email.senders_list'))
    finally:
        session.close()

@email_bp.route('/senders/<int:user_id>/enable', methods=['POST'])
def enable_sender(user_id: int):
    """Enable sender."""
    session = Session()
    try:
        sender = session.query(Sender).get(user_id)
        if not sender:
            flash('Sender not found', 'error')
            return redirect(url_for('email.senders_list'))
        
        sender_email = sender.email
        sender.is_active = True
        session.commit()
        
        flash(f'Sender {sender_email} enabled', 'success')
        return redirect(url_for('email.senders_list'))
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error enabling sender: {e}")
        flash(f'Error enabling sender: {str(e)}', 'error')
        return redirect(url_for('email.senders_list'))
    finally:
        session.close()

@email_bp.route('/senders/<int:user_id>/remove', methods=['POST'])
def remove_sender(user_id: int):
    """Permanently remove sender."""
    session = Session()
    try:
        sender = session.query(Sender).get(user_id)
        if not sender:
            flash('Sender not found', 'error')
            return redirect(url_for('email.senders_list'))
        
        sender_email = sender.email
        session.delete(sender)
        session.commit()
        
        flash(f'Sender {sender_email} permanently removed', 'success')
        return redirect(url_for('email.senders_list'))
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error removing sender: {e}")
        flash(f'Error removing sender: {str(e)}', 'error')
        return redirect(url_for('email.senders_list'))
    finally:
        session.close()

@email_bp.route('/senders/<int:user_id>/edit', methods=['GET', 'POST'])
def edit_sender(user_id: int):
    """Edit sender."""
    session = Session()
    try:
        sender = session.query(Sender).get(user_id)
        if not sender:
            flash('Sender not found', 'error')
            return redirect(url_for('email.senders_list'))
        
        domains = session.query(Domain).filter_by(is_active=True).order_by(Domain.domain_name).all()
        
        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '').strip()
            domain_id = request.form.get('domain_id', type=int)
            can_send_as_domain = request.form.get('can_send_as_domain') == 'on'
            store_message_content = request.form.get('store_message_content') == 'on'
            
            if not all([email, domain_id]):
                flash('Email and domain are required', 'error')
                return redirect(url_for('email.edit_sender', user_id=user_id))
            
            # Email validation
            if '@' not in email or '.' not in email.split('@')[1]:
                flash('Invalid email format', 'error')
                return redirect(url_for('email.edit_sender', user_id=user_id))
            
            # Check if email already exists (excluding current sender)
            existing = session.query(Sender).filter(
                Sender.email == email,
                Sender.id != user_id
            ).first()
            if existing:
                flash(f'Email {email} already exists', 'error')
                return redirect(url_for('email.edit_sender', user_id=user_id))
            
            # Update sender
            sender.email = email
            sender.domain_id = domain_id
            sender.can_send_as_domain = can_send_as_domain
            sender.store_message_content = store_message_content
            
            # Update password if provided
            if password:
                sender.password_hash = hash_password(password)
            
            session.commit()
            
            flash(f'Sender {email} updated successfully', 'success')
            return redirect(url_for('email.senders_list'))
        
        return render_template('edit_sender.html', sender=sender, domains=domains)
    
    except Exception as e:
        session.rollback()
        logger.error(f"Error editing sender: {e}")
        flash(f'Error editing sender: {str(e)}', 'error')
        return redirect(url_for('email.senders_list'))
    finally:
        session.close()