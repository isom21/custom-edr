"""Add tenant_id to playbook + playbook_run (CODE-8).

The playbook + playbook_run tables predate Phase 3 multi-tenancy and
shipped without a tenant_id column. Pre-PR, /api/playbooks listed
every tenant's playbooks to admins and let any admin mutate any
playbook by id; PlaybookRun history was equally unscoped.

This migration:

  * Adds ``tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001'``
    to ``playbook`` and ``playbook_run``. The default is the seed
    tenant so existing rows backfill against it; the column then
    keeps the FK to ``tenant.id`` like every other Phase-3 table.
  * Drops the existing global UNIQUE on ``playbook.name`` and replaces
    it with a (tenant_id, name) composite — so tenant A and tenant B
    can each have a "lsass-credential-dump-response" playbook.
  * Adds indexes on ``tenant_id`` for both tables so the router's
    ``WHERE tenant_id = ?`` filter doesn't degrade to a seq scan.

Downgrade reverses everything, restoring the global UNIQUE on
``playbook.name``. Re-applying the migration after a downgrade
on a multi-tenant DB would fail the UNIQUE — that's intentional;
the downgrade path is for emergency rollback, not routine use.

Revision ID: a1c2e3f4d5b6
Revises: f6f7a8b9c0d1
Create Date: 2026-05-15
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a1c2e3f4d5b6"
down_revision: str | None = "f6f7a8b9c0d1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


SEED_TENANT_ID = "00000000-0000-0000-0000-000000000001"


def upgrade() -> None:
    # ---- playbook -----------------------------------------------------
    op.add_column(
        "playbook",
        sa.Column(
            "tenant_id",
            sa.Uuid(),
            nullable=False,
            server_default=SEED_TENANT_ID,
        ),
    )
    op.create_foreign_key(
        "fk_playbook_tenant_id_tenant",
        "playbook",
        "tenant",
        ["tenant_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index("ix_playbook_tenant_id", "playbook", ["tenant_id"])
    # Drop the global UNIQUE(name) and replace with (tenant_id, name).
    # The original migration named the constraint via SQLAlchemy's
    # naming convention -> `uq_playbook_name`.
    op.drop_constraint("uq_playbook_name", "playbook", type_="unique")
    op.create_unique_constraint(
        "uq_playbook_tenant_id_name",
        "playbook",
        ["tenant_id", "name"],
    )

    # ---- playbook_run -------------------------------------------------
    op.add_column(
        "playbook_run",
        sa.Column(
            "tenant_id",
            sa.Uuid(),
            nullable=False,
            server_default=SEED_TENANT_ID,
        ),
    )
    op.create_foreign_key(
        "fk_playbook_run_tenant_id_tenant",
        "playbook_run",
        "tenant",
        ["tenant_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index("ix_playbook_run_tenant_id", "playbook_run", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_playbook_run_tenant_id", table_name="playbook_run")
    op.drop_constraint("fk_playbook_run_tenant_id_tenant", "playbook_run", type_="foreignkey")
    op.drop_column("playbook_run", "tenant_id")

    op.drop_constraint("uq_playbook_tenant_id_name", "playbook", type_="unique")
    op.create_unique_constraint("uq_playbook_name", "playbook", ["name"])
    op.drop_index("ix_playbook_tenant_id", table_name="playbook")
    op.drop_constraint("fk_playbook_tenant_id_tenant", "playbook", type_="foreignkey")
    op.drop_column("playbook", "tenant_id")
