"""Add sent_by_fuzzer column

Revision ID: eb55255c14f0
Revises: 
Create Date: 2021-09-28 13:42:04.995993

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'eb55255c14f0'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("request_response", sa.Column("sent_by_fuzzer", sa.Boolean, default=False, index=True))

def downgrade():
    op.drop_column("request_response", "sent_by_fuzzer")

