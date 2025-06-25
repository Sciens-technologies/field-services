"""Add ADMIN to DeviceAssignmentRole enum

Revision ID: c222f1508fbf
Revises: 942c571d2861
Create Date: 2025-06-25 11:46:27.094328

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c222f1508fbf'
down_revision: Union[str, None] = '942c571d2861'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add new values to DeviceAssignmentRole enum
    op.execute("ALTER TYPE deviceassignmentrole ADD VALUE IF NOT EXISTS 'MANAGER'")
    op.execute("ALTER TYPE deviceassignmentrole ADD VALUE IF NOT EXISTS 'ADMIN'")
    op.execute("ALTER TYPE deviceassignmentrole ADD VALUE IF NOT EXISTS 'WAREHOUSE'")
    op.execute("ALTER TYPE deviceassignmentrole ADD VALUE IF NOT EXISTS 'AGENT'")


def downgrade() -> None:
    """Downgrade schema."""
    # Note: PostgreSQL doesn't support removing enum values easily
    # This would require recreating the enum type
    pass
