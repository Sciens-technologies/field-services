"""add notification toggles

Revision ID: add_notification_toggles
Revises: initial_migration
Create Date: 2024-04-04 09:15:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_notification_toggles'
down_revision = 'initial_migration'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Add the toggle columns to user_notification_preferences
    op.add_column('user_notification_preferences', sa.Column('email_enabled', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('user_notification_preferences', sa.Column('sms_enabled', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('user_notification_preferences', sa.Column('push_enabled', sa.Boolean(), nullable=False, server_default='true'))

def downgrade() -> None:
    # Remove the toggle columns
    op.drop_column('user_notification_preferences', 'email_enabled')
    op.drop_column('user_notification_preferences', 'sms_enabled')
    op.drop_column('user_notification_preferences', 'push_enabled') 