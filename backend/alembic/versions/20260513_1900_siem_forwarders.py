"""Phase 1 #1.5 — SIEM forwarders (syslog/CEF + Splunk HEC + Sentinel).

Adds the `siem_destinations` table. Each row is an operator-registered
sink that the forwarder worker consumes telemetry + alerts into. The
`encrypted_config` column is Fernet-encrypted JSON; the worker
decrypts at send time and never logs the plaintext.

Phase-1 batch note: this migration shares `down_revision`
`7d3f8e1a2b4c` with three sibling Phase-1 PRs (MITRE fields, intel
feeds, alert routing). The merge orchestrator rebases whichever
sibling lands second so the chain stays linear. Standalone test
runs apply this directly on top of `7d3f8e1a2b4c`.

Revision ID: b94e7d2f15c8
Revises: 7d3f8e1a2b4c
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "b94e7d2f15c8"
down_revision: str | None = "a83f1c4e6d72"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_SIEM_KINDS = ["syslog_cef", "splunk_hec", "sentinel_hub"]


def upgrade() -> None:
    bind = op.get_bind()
    postgresql.ENUM(*_SIEM_KINDS, name="siem_kind").create(bind, checkfirst=True)
    siem_kind = postgresql.ENUM(name="siem_kind", create_type=False)

    op.create_table(
        "siem_destinations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("kind", siem_kind, nullable=False),
        # Fernet ciphertext of the destination config (URL, token, TLS
        # opts, etc.). LargeBinary because the ciphertext is bytes, not
        # text — matches the model's `Mapped[bytes]`.
        sa.Column("encrypted_config", sa.LargeBinary(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_send_at", sa.DateTime(timezone=True), nullable=True),
        # Lag/error_count are operator-facing health metrics that the
        # forwarder worker updates per-send. Lag stored as double
        # precision so seconds-since-event is unambiguous regardless of
        # the underlying clock resolution.
        sa.Column(
            "lag_seconds",
            sa.Float(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "error_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("name", name="uq_siem_destinations_name"),
    )
    op.create_index("ix_siem_destinations_kind", "siem_destinations", ["kind"])
    op.create_index("ix_siem_destinations_enabled", "siem_destinations", ["enabled"])


def downgrade() -> None:
    op.drop_index("ix_siem_destinations_enabled", table_name="siem_destinations")
    op.drop_index("ix_siem_destinations_kind", table_name="siem_destinations")
    op.drop_table("siem_destinations")
    op.execute("DROP TYPE IF EXISTS siem_kind")
