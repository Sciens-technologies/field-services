"""add phone number to users

Revision ID: add_phone_number_to_users
Revises: 217fbed9cba7
Create Date: 2023-01-01T00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector

# revision identifiers, used by Alembic.
revision = 'add_phone_number_to_users'
down_revision = '217fbed9cba7'  # Update this to your latest migration
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade schema."""
    # Check if phone_number column exists before trying to add it
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    columns = [c['name'] for c in inspector.get_columns('users')]
    
    if 'phone_number' not in columns:
        op.add_column('users', sa.Column('phone_number', sa.String(20), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    # Check if phone_number column exists before trying to drop it
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    columns = [c['name'] for c in inspector.get_columns('users')]
    
    if 'phone_number' in columns:
        op.drop_column('users', 'phone_number')