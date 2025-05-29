"""remove_name_column_from_users

Revision ID: 217fbed9cba7
Revises: 11596be55f4e
Create Date: 2025-05-15 17:38:32.747801

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector


# revision identifiers, used by Alembic.
revision: str = '217fbed9cba7'
down_revision: Union[str, None] = '11596be55f4e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Check if name column exists before trying to drop it
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    columns = [c['name'] for c in inspector.get_columns('users')]
    
    if 'name' in columns:
        # Make sure all data from name is properly migrated to first_name and last_name
        op.execute("""
        UPDATE users 
        SET 
          first_name = SPLIT_PART(name, ' ', 1),
          last_name = SUBSTRING(name FROM POSITION(' ' IN name) + 1)
        WHERE name IS NOT NULL AND (first_name IS NULL OR first_name = '')
        """)
        
        # Drop the name column
        op.drop_column('users', 'name')


def downgrade() -> None:
    """Downgrade schema."""
    # Check if name column doesn't exist before trying to add it
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    columns = [c['name'] for c in inspector.get_columns('users')]
    
    if 'name' not in columns:
        # Add the name column back
        op.add_column('users', sa.Column('name', sa.String(100), nullable=True))
        
        # Reconstruct name from first_name and last_name
        op.execute("""
        UPDATE users 
        SET name = CONCAT(first_name, ' ', last_name)
        WHERE first_name IS NOT NULL
        """)


