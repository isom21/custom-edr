"""M9.5: hosts.capabilities column

Adds the comma-separated capability-flags column populated from the
agent's Hello. Used by M14 fleet-rollout dashboards to show which
hosts support which features (self_protect_v1, spool_v1, etc.).

Revision ID: 9c1d3e7a6b22
Revises: 7a4f0c2e9fa1
Create Date: 2026-05-10
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "9c1d3e7a6b22"
down_revision: Union[str, None] = "7a4f0c2e9fa1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("hosts", sa.Column("capabilities", sa.String(length=1024), nullable=True))


def downgrade() -> None:
    op.drop_column("hosts", "capabilities")
