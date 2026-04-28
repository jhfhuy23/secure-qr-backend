"""Initial schema — scanned_urls, blacklisted_urls, reports

Revision ID: 001
Revises:
Create Date: 2025-01-01 00:00:00
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision:       str                             = "001"
down_revision:  Union[str, None]                = None
branch_labels:  Union[str, Sequence[str], None] = None
depends_on:     Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── scanned_urls ──────────────────────────────────────────────────────────
    op.create_table(
        "scanned_urls",
        sa.Column("id",              sa.BigInteger(),                    nullable=False),
        sa.Column("device_id",       sa.String(64),                      nullable=False),
        sa.Column("raw_url",         sa.Text(),                          nullable=False),
        sa.Column("url_hash",        sa.String(64),                      nullable=False),
        sa.Column("domain",          sa.String(253),                     nullable=False),
        sa.Column("safety_score",    sa.SmallInteger(),                  nullable=False),
        sa.Column("safety_label",    sa.String(20),                      nullable=False),
        sa.Column("was_blacklisted", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("threat_type",     sa.String(50),                      nullable=True),
        sa.Column("scanned_at",      sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_scanned_device", "scanned_urls", ["device_id"])
    op.create_index("idx_scanned_hash",   "scanned_urls", ["url_hash"])
    op.create_index("idx_scanned_at",     "scanned_urls", ["scanned_at"], postgresql_using="btree")
    op.create_index("idx_scanned_label",  "scanned_urls", ["safety_label"])

    # ── blacklisted_urls ──────────────────────────────────────────────────────
    op.create_table(
        "blacklisted_urls",
        sa.Column("id",                sa.BigInteger(),                         nullable=False),
        sa.Column("url",               sa.Text(),                               nullable=False),
        sa.Column("url_hash",          sa.String(64),                           nullable=False),
        sa.Column("domain",            sa.String(253),                          nullable=False),
        sa.Column("threat_type",       sa.String(50),                           nullable=False),
        sa.Column("severity",          sa.SmallInteger(), server_default="5",   nullable=False),
        sa.Column("source",            sa.String(50),                           nullable=False),
        sa.Column("is_active",         sa.Boolean(),      server_default="true", nullable=False),
        sa.Column("added_at",          sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("last_confirmed_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("notes",             sa.Text(),                               nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("url_hash", name="uq_blacklist_url_hash"),
    )
    op.create_index("idx_blacklist_hash",   "blacklisted_urls", ["url_hash"], unique=True)
    op.create_index("idx_blacklist_domain", "blacklisted_urls", ["domain"])
    op.create_index(
        "idx_blacklist_active_hash",
        "blacklisted_urls",
        ["url_hash"],
        postgresql_where=sa.text("is_active = TRUE"),
    )

    # ── reports ───────────────────────────────────────────────────────────────
    op.create_table(
        "reports",
        sa.Column("id",          sa.BigInteger(),                          nullable=False),
        sa.Column("device_id",   sa.String(64),                            nullable=False),
        sa.Column("url",         sa.Text(),                                nullable=False),
        sa.Column("url_hash",    sa.String(64),                            nullable=False),
        sa.Column("reason",      sa.Text(),                                nullable=True),
        sa.Column("status",      sa.String(20), server_default="pending",  nullable=False),
        sa.Column("created_at",  sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("reviewed_at", sa.TIMESTAMP(timezone=True),              nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_reports_status", "reports", ["status"])
    op.create_index("idx_reports_hash",   "reports", ["url_hash"])


def downgrade() -> None:
    op.drop_table("reports")
    op.drop_table("blacklisted_urls")
    op.drop_table("scanned_urls")