"""
Database migrations for CTFd Tailscale Plugin.

Migrations are handled by CTFd's built-in migration system (CTFd.plugins.migrations).
Each migration file should have:
- revision: unique identifier for this migration
- down_revision: the previous migration (None for the first)
- upgrade(op): function that applies the migration using Alembic Operations
- downgrade(op): optional function to reverse the migration
"""
