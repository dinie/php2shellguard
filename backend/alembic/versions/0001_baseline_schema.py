"""baseline stats schema (idempotent)

Creates checks / stream_state / host_registry with their indexes. Existing
databases from before Alembic was introduced are adopted in place: tables and
indexes that already exist are left untouched, and only the missing pieces
(primarily `checks.origin`) are added.

Revision ID: 0001
Revises:
Create Date: 2026-10-22

"""

import sqlalchemy as sa

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

_ORIGIN_DEFAULT = sa.text("'extension'")


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())

    if "checks" in tables:
        columns = {column["name"] for column in inspector.get_columns("checks")}
        if "origin" not in columns:
            op.add_column(
                "checks",
                sa.Column(
                    "origin", sa.Text(), server_default=_ORIGIN_DEFAULT, nullable=False
                ),
            )
    else:
        op.create_table(
            "checks",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("host", sa.Text(), nullable=False),
            sa.Column("status", sa.Text(), nullable=False),
            sa.Column("php_version", sa.Text(), nullable=True),
            sa.Column("source", sa.Text(), nullable=True),
            sa.Column(
                "origin", sa.Text(), server_default=_ORIGIN_DEFAULT, nullable=False
            ),
            sa.Column("checked_at", sa.Text(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )

    indexes = {
        index["name"] for index in inspector.get_indexes("checks")
    }
    if "idx_checks_host" not in indexes:
        op.create_index("idx_checks_host", "checks", ["host"])
    if "idx_checks_checked_at" not in indexes:
        op.create_index("idx_checks_checked_at", "checks", ["checked_at"])

    if "stream_state" not in tables:
        op.create_table(
            "stream_state",
            sa.Column("key", sa.Text(), nullable=False),
            sa.Column("value", sa.Text(), nullable=True),
            sa.PrimaryKeyConstraint("key"),
        )

    if "host_registry" not in tables:
        op.create_table(
            "host_registry",
            sa.Column("host", sa.Text(), nullable=False),
            sa.Column("original_status", sa.Text(), nullable=False),
            sa.Column("original_checked_at", sa.Text(), nullable=False),
            sa.Column("current_status", sa.Text(), nullable=False),
            sa.Column("current_checked_at", sa.Text(), nullable=False),
            sa.PrimaryKeyConstraint("host"),
        )


def downgrade() -> None:
    op.drop_table("host_registry")
    op.drop_table("stream_state")
    op.drop_index("idx_checks_checked_at", table_name="checks")
    op.drop_index("idx_checks_host", table_name="checks")
    op.drop_table("checks")
