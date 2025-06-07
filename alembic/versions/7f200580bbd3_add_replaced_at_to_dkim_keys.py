"""add_replaced_at_to_dkim_keys

Revision ID: 7f200580bbd3
Revises: d02f993649e8
Create Date: 2025-06-07 12:48:07.930008

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7f200580bbd3'
down_revision: Union[str, None] = 'd02f993649e8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add replaced_at field to DKIM keys table."""
    op.add_column('esrv_dkim_keys', sa.Column('replaced_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    """Remove replaced_at field from DKIM keys table."""
    op.drop_column('esrv_dkim_keys', 'replaced_at')
