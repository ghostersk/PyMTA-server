"""Add legacy EmailLog columns for backward compatibility

Revision ID: d02f993649e8
Revises: 53036910f343
Create Date: 2025-06-01 11:50:54.362830

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd02f993649e8'
down_revision: Union[str, None] = '53036910f343'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add legacy columns for backward compatibility with existing EmailRelay code
    op.add_column('esrv_email_logs', sa.Column('message_id', sa.String(), nullable=True))
    op.add_column('esrv_email_logs', sa.Column('timestamp', sa.DateTime(), nullable=True))
    op.add_column('esrv_email_logs', sa.Column('peer', sa.String(), nullable=True))
    op.add_column('esrv_email_logs', sa.Column('mail_from', sa.String(), nullable=True))
    op.add_column('esrv_email_logs', sa.Column('rcpt_tos', sa.String(), nullable=True))
    op.add_column('esrv_email_logs', sa.Column('content', sa.Text(), nullable=True))
    op.add_column('esrv_email_logs', sa.Column('dkim_signed', sa.Boolean(), nullable=True, default=False))


def downgrade() -> None:
    """Downgrade schema."""
    # Remove the legacy columns
    op.drop_column('esrv_email_logs', 'dkim_signed')
    op.drop_column('esrv_email_logs', 'content')
    op.drop_column('esrv_email_logs', 'rcpt_tos')
    op.drop_column('esrv_email_logs', 'mail_from')
    op.drop_column('esrv_email_logs', 'peer')
    op.drop_column('esrv_email_logs', 'timestamp')
    op.drop_column('esrv_email_logs', 'message_id')
