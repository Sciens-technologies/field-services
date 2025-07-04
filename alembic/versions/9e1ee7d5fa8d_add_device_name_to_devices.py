"""add device_name to devices

Revision ID: 9e1ee7d5fa8d
Revises: da7925daa93e
Create Date: 2025-07-03 13:35:43.992941

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9e1ee7d5fa8d'
down_revision: Union[str, None] = 'da7925daa93e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('devices', sa.Column('device_name', sa.String(length=100), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('devices', 'device_name')
    # ### end Alembic commands ###
