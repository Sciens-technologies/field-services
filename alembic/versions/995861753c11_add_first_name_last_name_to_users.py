"""add_first_name_last_name_to_users

Revision ID: 995861753c11
Revises: 20222cdacb43
Create Date: 2025-05-15 17:28:37.364545

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '995861753c11'
down_revision: Union[str, None] = '20222cdacb43'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add first_name and last_name columns if they don't exist
    op.add_column('users', sa.Column('first_name', sa.String(length=50), nullable=True), schema=None)
    op.add_column('users', sa.Column('last_name', sa.String(length=50), nullable=True), schema=None)
    
    # Update existing users to split their name into first_name and last_name (if needed)
    op.execute("""
    UPDATE users 
    SET 
      first_name = SPLIT_PART(name, ' ', 1),
      last_name = SUBSTRING(name FROM POSITION(' ' IN name) + 1)
    WHERE name IS NOT NULL AND first_name IS NULL
    """)
    
    # Make sure the roles table has the 'agent' role
    op.execute("""
    INSERT INTO roles (name) 
    VALUES ('agent')
    ON CONFLICT (name) DO NOTHING
    """)


def downgrade() -> None:
    """Downgrade schema."""
    # Drop first_name and last_name columns
    op.drop_column('users', 'first_name', schema=None)
    op.drop_column('users', 'last_name', schema=None)

