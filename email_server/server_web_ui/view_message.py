"""
Route to view full email message content if stored.
"""
from flask import render_template, abort, flash, redirect, Response, send_file, request, url_for
from email_server.models import Session, EmailLog, EmailAttachment
from email_server.tool_box import get_logger
from .routes import email_bp
import os

logger = get_logger()

@email_bp.route('/msg/content/<int:log_id>')
def view_message_content(log_id):
    """View the full message content for an email log if stored."""
    session = Session()
    try:
        # Get log with attachments
        log = session.query(EmailLog).filter_by(id=log_id).first()
        if not log:
            abort(404)
            
        # Get attachments for this log
        attachments = session.query(EmailAttachment).filter_by(email_log_id=log_id).all()
        log.attachments = attachments
        
        return render_template('view_message_content.html', log=log)
    finally:
        session.close()
@email_bp.route('/msg/attachment/<int:attachment_id>/download')
def download_attachment(attachment_id):
    session = Session()
    try:
        attachment = session.query(EmailAttachment).get(attachment_id)
        if not attachment or not os.path.isfile(attachment.file_path):
            flash('Attachment not found.', 'danger')
            return redirect(url_for('email.logs', type='emails'))

        # Get the normalized content type and handle special cases
        content_type = attachment.content_type.lower() if attachment.content_type else 'application/octet-stream'
        extension = os.path.splitext(attachment.filename.lower())[1][1:] if '.' in attachment.filename else ''
        
        # Force download if requested
        as_attachment = request.args.get('download', '').lower() == 'true'

        # Map of extensions to content types for common files
        content_type_map = {
            'txt': 'text/plain',
            'csv': 'text/csv',
            'pdf': 'application/pdf',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'svg': 'image/svg+xml',
            'html': 'text/html',
            'htm': 'text/html',
            'json': 'application/json',
            'xml': 'text/xml',
            'md': 'text/markdown',
        }

        # Update content type based on file extension if needed
        if content_type == 'application/octet-stream' and extension in content_type_map:
            content_type = content_type_map[extension]

        # Special handling for CSV files
        if content_type == 'text/csv' and not as_attachment:
            try:
                with open(attachment.file_path, 'r') as f:
                    csv_content = f.read()
                # Create a simple HTML table view for CSV
                html_content = '<html><head><style>'
                html_content += 'table {border-collapse: collapse; width: 100%;} '
                html_content += 'th, td {border: 1px solid #ddd; padding: 8px; text-align: left;} '
                html_content += 'tr:nth-child(even) {background-color: #f2f2f2;} '
                html_content += 'th {background-color: #4CAF50; color: white;}'
                html_content += '</style></head><body><table>'
                
                # Convert CSV to HTML table
                for i, line in enumerate(csv_content.split('\n')):
                    if not line.strip():
                        continue
                    html_content += '<tr>'
                    if i == 0:  # Header row
                        html_content += ''.join(f'<th>{cell}</th>' for cell in line.split(','))
                    else:
                        html_content += ''.join(f'<td>{cell}</td>' for cell in line.split(','))
                    html_content += '</tr>'
                
                html_content += '</table></body></html>'
                return Response(html_content, mimetype='text/html')
            except Exception as e:
                logger.warning(f"Failed to create CSV preview: {e}")
                # Fall back to normal file handling

        # Determine if the file should be viewed in browser
        if as_attachment:
            # Force download
            return send_file(
                attachment.file_path,
                as_attachment=True,
                download_name=attachment.filename
            )
        else:
            # Try to display in browser
            return send_file(
                attachment.file_path,
                mimetype=content_type
            )
    finally:
        session.close()


@email_bp.route('/msg/attachment/<int:attachment_id>/delete', methods=['POST', 'GET'])
def delete_attachment(attachment_id):
    session = Session()
    try:
        attachment = session.query(EmailAttachment).get(attachment_id)
        if not attachment:
            flash('Attachment not found.', 'danger')
            return redirect(url_for('email.logs', type='emails'))
        # Remove file from disk
        if os.path.isfile(attachment.file_path):
            os.remove(attachment.file_path)
        # Remove from DB
        session.delete(attachment)
        session.commit()
        flash('Attachment deleted.', 'success')
        return redirect(url_for('email.logs', type='emails'))
    finally:
        session.close()