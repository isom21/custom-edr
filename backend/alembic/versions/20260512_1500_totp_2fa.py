"""Add TOTP 2FA columns to users.

Per-user opt-in TOTP. The columns are nullable so existing rows stay
valid; `totp_enabled` defaults to False and gates the 2FA challenge
on login. See `app/services/totp.py` for the encrypt/verify path and
`app/api/auth.py` for the two-step login flow.

Revision ID: f1a2b3c4d5e6
Revises: c41d5b7e9f02
Create Date: 2026-05-12
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f1a2b3c4d5e6"
down_revision: str | None = "c41d5b7e9f02"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("users", sa.Column("totp_secret_encrypted", sa.LargeBinary(), nullable=True))
    op.add_column(
        "users", sa.Column("totp_pending_secret_encrypted", sa.LargeBinary(), nullable=True)
    )
    op.add_column("users", sa.Column("totp_recovery_codes_hashed", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "totp_recovery_codes_hashed")
    op.drop_column("users", "totp_pending_secret_encrypted")
    op.drop_column("users", "totp_secret_encrypted")
    op.drop_column("users", "totp_enabled")
