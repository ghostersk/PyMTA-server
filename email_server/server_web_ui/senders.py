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
from email_server.models import Session, Domain, User
from email_server.tool_box import get_logger
import bcrypt
from .routes import email_bp
from email_server.models import Session, Domain, User, hash_password

logger = get_logger()

@email_bp.route('/senders')
def senders_list():
    """List all users."""
    session = Session()
    try:
        users = session.query(User, Domain).join(Domain, User.domain_id == Domain.id).order_by(User.email).all()
        return render_template('senders.html', users=users)
    finally:
        session.close()

@email_bp.route('/senders/add', methods=['GET', 'POST'])
def add_sender():
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
                return redirect(url_for('email.add_sender'))
            
            # Validate email format
            if '@' not in email:
                flash('Invalid email format', 'error')
                return redirect(url_for('email.add_sender'))
            
            # Check if user already exists
            existing = session.query(User).filter_by(email=email).first()
            if existing:
                flash(f'User {email} already exists', 'error')
                return redirect(url_for('email.senders_list'))
            
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
            return redirect(url_for('email.senders_list'))
        
        return render_template('add_sender.html', domains=domains)
    
    except Exception as e:
        session.rollback()
        logger.error(f"Error adding user: {e}")
        flash(f'Error adding user: {str(e)}', 'error')
        return redirect(url_for('email.add_sender'))
    finally:
        session.close()

@email_bp.route('/senders/<int:user_id>/delete', methods=['POST'])
def delete_sender(user_id: int):
    """Disable user (soft delete)."""
    session = Session()
    try:
        user = session.query(User).get(user_id)
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('email.senders_list'))
        
        user_email = user.email
        user.is_active = False
        session.commit()
        
        flash(f'User {user_email} disabled', 'success')
        return redirect(url_for('email.senders_list'))
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error disabling user: {e}")
        flash(f'Error disabling user: {str(e)}', 'error')
        return redirect(url_for('email.senders_list'))
    finally:
        session.close()

@email_bp.route('/senders/<int:user_id>/enable', methods=['POST'])
def enable_sender(user_id: int):
    """Enable user."""
    session = Session()
    try:
        user = session.query(User).get(user_id)
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('email.senders_list'))
        
        user_email = user.email
        user.is_active = True
        session.commit()
        
        flash(f'User {user_email} enabled', 'success')
        return redirect(url_for('email.senders_list'))
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error enabling user: {e}")
        flash(f'Error enabling user: {str(e)}', 'error')
        return redirect(url_for('email.senders_list'))
    finally:
        session.close()

@email_bp.route('/senders/<int:user_id>/remove', methods=['POST'])
def remove_sender(user_id: int):
    """Permanently remove user."""
    session = Session()
    try:
        user = session.query(User).get(user_id)
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('email.senders_list'))
        
        user_email = user.email
        session.delete(user)
        session.commit()
        
        flash(f'User {user_email} permanently removed', 'success')
        return redirect(url_for('email.senders_list'))
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error removing user: {e}")
        flash(f'Error removing user: {str(e)}', 'error')
        return redirect(url_for('email.senders_list'))
    finally:
        session.close()

@email_bp.route('/senders/<int:user_id>/edit', methods=['GET', 'POST'])
def edit_sender(user_id: int):
    """Edit user."""
    session = Session()
    try:
        user = session.query(User).get(user_id)
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('email.senders_list'))
        
        domains = session.query(Domain).filter_by(is_active=True).order_by(Domain.domain_name).all()
        
        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '').strip()
            domain_id = request.form.get('domain_id', type=int)
            can_send_as_domain = request.form.get('can_send_as_domain') == 'on'
            
            if not all([email, domain_id]):
                flash('Email and domain are required', 'error')
                return redirect(url_for('email.edit_sender', user_id=user_id))
            
            # Email validation
            if '@' not in email or '.' not in email.split('@')[1]:
                flash('Invalid email format', 'error')
                return redirect(url_for('email.edit_sender', user_id=user_id))
            
            # Check if email already exists (excluding current user)
            existing = session.query(User).filter(
                User.email == email,
                User.id != user_id
            ).first()
            if existing:
                flash(f'Email {email} already exists', 'error')
                return redirect(url_for('email.edit_sender', user_id=user_id))
            
            # Update user
            user.email = email
            user.domain_id = domain_id
            user.can_send_as_domain = can_send_as_domain
            
            # Update password if provided
            if password:
                user.password_hash = hash_password(password)
            
            session.commit()
            
            flash(f'User {email} updated successfully', 'success')
            return redirect(url_for('email.senders_list'))
        
        return render_template('edit_sender.html', user=user, domains=domains)
    
    except Exception as e:
        session.rollback()
        logger.error(f"Error editing user: {e}")
        flash(f'Error editing user: {str(e)}', 'error')
        return redirect(url_for('email.senders_list'))
    finally:
        session.close()