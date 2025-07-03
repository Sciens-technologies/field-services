"""add category to work_order_templates

Revision ID: add_category_to_work_order_templates
Revises: 942c571d2861
Create Date: 2024-06-25
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_category_to_work_order_templates'
down_revision = '942c571d2861'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('work_order_templates', sa.Column('category', sa.String(length=16), nullable=False, server_default='ZDEV'))
    op.alter_column('work_order_templates', 'category', server_default=None)

def downgrade():
    op.drop_column('work_order_templates', 'category') 