"""
Migration: Add custom_tags column to tailscale_user_keys table

Revision ID: 001_add_custom_tags
Revises: None
"""
import logging

from sqlalchemy import text

logger = logging.getLogger(__name__)

# Alembic revision identifiers
revision = "001_add_custom_tags"
down_revision = None


def upgrade(op):
    """
    Add custom_tags column to the tailscale_user_keys table.

    This migration is idempotent - it checks if the column exists before adding it.
    """
    from sqlalchemy import inspect as sa_inspect

    bind = op.get_bind()
    inspector = sa_inspect(bind)
    table_name = "tailscale_user_keys"

    # Check if table exists
    if table_name not in inspector.get_table_names():
        logger.info("Table %s does not exist yet, skipping migration", table_name)
        return

    # Check if column already exists
    columns = [col["name"] for col in inspector.get_columns(table_name)]
    if "custom_tags" in columns:
        logger.info("Column 'custom_tags' already exists, skipping migration")
        return

    # Add the column
    logger.info("Adding 'custom_tags' column to %s table", table_name)
    bind.execute(text(f"ALTER TABLE {table_name} ADD COLUMN custom_tags TEXT"))
    logger.info("Migration completed successfully")


def downgrade(op):
    """
    Remove custom_tags column from the tailscale_user_keys table.

    WARNING: This will delete all custom tags data!
    """
    from sqlalchemy import inspect as sa_inspect

    bind = op.get_bind()
    inspector = sa_inspect(bind)
    table_name = "tailscale_user_keys"

    # Check if table exists
    if table_name not in inspector.get_table_names():
        logger.info("Table %s does not exist, skipping downgrade", table_name)
        return

    # Check if column exists
    columns = [col["name"] for col in inspector.get_columns(table_name)]
    if "custom_tags" not in columns:
        logger.info("Column 'custom_tags' does not exist, skipping downgrade")
        return

    dialect = bind.dialect.name
    if dialect == "sqlite":
        logger.error("SQLite doesn't support DROP COLUMN in all versions")
        raise NotImplementedError("SQLite DROP COLUMN not supported")

    logger.warning("Removing 'custom_tags' column - all custom tags data will be lost!")
    bind.execute(text(f"ALTER TABLE {table_name} DROP COLUMN custom_tags"))
    logger.info("Downgrade completed successfully")
