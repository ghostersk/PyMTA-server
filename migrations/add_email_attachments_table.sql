-- Migration: Add EmailAttachment table for storing email attachments on disk
CREATE TABLE IF NOT EXISTS esrv_email_attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_log_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    content_type TEXT,
    file_path TEXT NOT NULL,
    size INTEGER,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(email_log_id) REFERENCES esrv_email_logs(id) ON DELETE CASCADE
);
