"""Merge heads

Revision ID: 337c2c6c233b
Revises: add_category_to_work_order_templates, c222f1508fbf
Create Date: 2025-07-01 18:13:26.065453

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '337c2c6c233b'
down_revision: Union[str, None] = ('add_category_to_work_order_templates', 'c222f1508fbf')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
