"""
Database migrations system for MongoDB - managing schema changes and versioning.

This module provides:
1. Migration version tracking
2. Forward and backward migration support
3. Schema change management (collections, indexes, validation rules)
4. Transaction safety
5. Migration validation
"""

import os
import re
import json
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable, Union
from pathlib import Path
import asyncio
import logging
from dataclasses import dataclass, asdict

from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorCollection
from pymongo.errors import OperationFailure, DuplicateKeyError
from pymongo import IndexModel, ASCENDING, DESCENDING

from app._core.config import get_settings
from app._core.database.connection import get_connection_manager
from app._core.database.session_manager import create_session, create_transaction
from app._core.utils.exceptions import MigrationError, DatabaseError
from app._core.utils.helpers import ensure_directory


logger = logging.getLogger(__name__)


@dataclass
class MigrationInfo:
    """Information about a migration."""

    version: str
    name: str
    description: str
    created_at: datetime
    applied_at: Optional[datetime] = None
    checksum: str = ""
    execution_time_ms: int = 0


@dataclass
class MigrationOperation:
    """A single migration operation."""

    operation_type: str  # 'create_collection', 'drop_collection', 'create_index', 'update_documents', etc.
    collection_name: str
    operation_data: Dict[str, Any]
    reversible: bool = True


@dataclass
class MigrationScript:
    """A migration script with forward and backward operations."""

    version: str
    name: str
    description: str
    up_operations: List[MigrationOperation]
    down_operations: List[MigrationOperation]
    created_at: datetime
    checksum: str


class MigrationRunner:
    """Handles execution of individual migrations for MongoDB."""

    def __init__(self, database: AsyncIOMotorDatabase, tenant_id: Optional[str] = None):
        self.database = database
        self.tenant_id = tenant_id

    async def execute_migration(
        self, migration: MigrationScript, direction: str = "up"
    ) -> int:
        """Execute a migration script and return execution time in milliseconds."""
        start_time = datetime.now()

        try:
            operations = (
                migration.up_operations
                if direction == "up"
                else migration.down_operations
            )

            if not operations:
                raise MigrationError(
                    f"No {direction} operations found for migration {migration.version}"
                )

            # Execute within a session with transaction
            async with create_session(self.tenant_id) as session:
                async with create_transaction(session) as transaction:
                    for operation in operations:
                        await self._execute_operation(operation, transaction)

                    logger.info(
                        f"Executed {direction} migration: {migration.version} - {migration.name} "
                        f"({len(operations)} operations)"
                    )

        except Exception as e:
            logger.error(
                f"Failed to execute {direction} migration {migration.version}: {str(e)}"
            )
            raise MigrationError(f"Migration {migration.version} failed: {str(e)}")

        end_time = datetime.now()
        execution_time = int((end_time - start_time).total_seconds() * 1000)

        return execution_time

    async def _execute_operation(
        self, operation: MigrationOperation, transaction
    ) -> None:
        """Execute a single migration operation."""
        collection = self.database[operation.collection_name]

        try:
            if operation.operation_type == "create_collection":
                await self._create_collection(operation, transaction)

            elif operation.operation_type == "drop_collection":
                await self._drop_collection(operation, transaction)

            elif operation.operation_type == "create_index":
                await self._create_index(operation, collection, transaction)

            elif operation.operation_type == "drop_index":
                await self._drop_index(operation, collection, transaction)

            elif operation.operation_type == "update_documents":
                await self._update_documents(operation, collection, transaction)

            elif operation.operation_type == "insert_documents":
                await self._insert_documents(operation, collection, transaction)

            elif operation.operation_type == "delete_documents":
                await self._delete_documents(operation, collection, transaction)

            elif operation.operation_type == "rename_collection":
                await self._rename_collection(operation, transaction)

            elif operation.operation_type == "add_validation":
                await self._add_validation(operation, transaction)

            elif operation.operation_type == "remove_validation":
                await self._remove_validation(operation, transaction)

            else:
                raise MigrationError(
                    f"Unknown operation type: {operation.operation_type}"
                )

        except Exception as e:
            logger.error(
                f"Operation {operation.operation_type} failed on {operation.collection_name}: {str(e)}"
            )
            raise

    async def _create_collection(
        self, operation: MigrationOperation, transaction
    ) -> None:
        """Create a new collection."""
        collection_name = operation.collection_name
        options = operation.operation_data.get("options", {})

        await self.database.create_collection(
            collection_name, session=transaction.session_ctx.session, **options
        )
        logger.debug(f"Created collection: {collection_name}")

    async def _drop_collection(
        self, operation: MigrationOperation, transaction
    ) -> None:
        """Drop a collection."""
        collection_name = operation.collection_name
        collection = self.database[collection_name]

        await collection.drop(session=transaction.session_ctx.session)
        logger.debug(f"Dropped collection: {collection_name}")

    async def _create_index(
        self,
        operation: MigrationOperation,
        collection: AsyncIOMotorCollection,
        transaction,
    ) -> None:
        """Create an index."""
        index_data = operation.operation_data

        # Build index specification
        index_spec = []
        for field, direction in index_data["fields"].items():
            index_spec.append((field, ASCENDING if direction > 0 else DESCENDING))

        # Create index model
        index_model = IndexModel(
            index_spec,
            name=index_data.get("name"),
            unique=index_data.get("unique", False),
            sparse=index_data.get("sparse", False),
            background=index_data.get("background", True),
            **index_data.get("options", {}),
        )

        await collection.create_indexes(
            [index_model], session=transaction.session_ctx.session
        )
        logger.debug(f"Created index {index_data.get('name')} on {collection.name}")

    async def _drop_index(
        self,
        operation: MigrationOperation,
        collection: AsyncIOMotorCollection,
        transaction,
    ) -> None:
        """Drop an index."""
        index_name = operation.operation_data["name"]

        await collection.drop_index(index_name, session=transaction.session_ctx.session)
        logger.debug(f"Dropped index {index_name} on {collection.name}")

    async def _update_documents(
        self,
        operation: MigrationOperation,
        collection: AsyncIOMotorCollection,
        transaction,
    ) -> None:
        """Update documents in a collection."""
        filter_query = operation.operation_data.get("filter", {})
        update_query = operation.operation_data["update"]
        options = operation.operation_data.get("options", {})

        result = await collection.update_many(
            filter_query,
            update_query,
            session=transaction.session_ctx.session,
            **options,
        )
        logger.debug(f"Updated {result.modified_count} documents in {collection.name}")

    async def _insert_documents(
        self,
        operation: MigrationOperation,
        collection: AsyncIOMotorCollection,
        transaction,
    ) -> None:
        """Insert documents into a collection."""
        documents = operation.operation_data["documents"]

        if isinstance(documents, list):
            result = await collection.insert_many(
                documents, session=transaction.session_ctx.session
            )
            logger.debug(
                f"Inserted {len(result.inserted_ids)} documents into {collection.name}"
            )
        else:
            result = await collection.insert_one(
                documents, session=transaction.session_ctx.session
            )
            logger.debug(f"Inserted 1 document into {collection.name}")

    async def _delete_documents(
        self,
        operation: MigrationOperation,
        collection: AsyncIOMotorCollection,
        transaction,
    ) -> None:
        """Delete documents from a collection."""
        filter_query = operation.operation_data["filter"]

        result = await collection.delete_many(
            filter_query, session=transaction.session_ctx.session
        )
        logger.debug(f"Deleted {result.deleted_count} documents from {collection.name}")

    async def _rename_collection(
        self, operation: MigrationOperation, transaction
    ) -> None:
        """Rename a collection."""
        old_name = operation.collection_name
        new_name = operation.operation_data["new_name"]

        await self.database[old_name].rename(
            new_name, session=transaction.session_ctx.session
        )
        logger.debug(f"Renamed collection {old_name} to {new_name}")

    async def _add_validation(self, operation: MigrationOperation, transaction) -> None:
        """Add validation rules to a collection."""
        collection_name = operation.collection_name
        validation_rules = operation.operation_data["validator"]
        validation_level = operation.operation_data.get("validationLevel", "strict")
        validation_action = operation.operation_data.get("validationAction", "error")

        await self.database.command(
            {
                "collMod": collection_name,
                "validator": validation_rules,
                "validationLevel": validation_level,
                "validationAction": validation_action,
            },
            session=transaction.session_ctx.session,
        )
        logger.debug(f"Added validation rules to {collection_name}")

    async def _remove_validation(
        self, operation: MigrationOperation, transaction
    ) -> None:
        """Remove validation rules from a collection."""
        collection_name = operation.collection_name

        await self.database.command(
            {"collMod": collection_name, "validator": {}},
            session=transaction.session_ctx.session,
        )
        logger.debug(f"Removed validation rules from {collection_name}")


class MigrationManager:
    """Main migration management system for MongoDB."""

    def __init__(
        self, database_name: Optional[str] = None, tenant_id: Optional[str] = None
    ):
        self.settings = get_settings()
        self.database_name = database_name or self.settings.database.database
        self.tenant_id = tenant_id
        self.migrations_collection_name = "migrations"

        # Migration directories
        self.migrations_dir = Path("migrations")
        self.tenant_migrations_dir = Path("migrations/tenants") if tenant_id else None

        # Ensure directories exist
        ensure_directory(self.migrations_dir)
        if self.tenant_migrations_dir:
            ensure_directory(self.tenant_migrations_dir)

    async def initialize(self) -> None:
        """Initialize migration system."""
        # Create migrations tracking collection
        manager = await get_connection_manager()
        async with manager.get_database() as db:
            # Create migrations collection if it doesn't exist
            collections = await db.list_collection_names()
            if self.migrations_collection_name not in collections:
                await db.create_collection(self.migrations_collection_name)

                # Create index for version uniqueness
                migrations_collection = db[self.migrations_collection_name]
                await migrations_collection.create_index([("version", 1)], unique=True)

                logger.info("Migrations collection created and indexed")

    async def create_migration(
        self,
        name: str,
        description: str = "",
        up_operations: Optional[List[MigrationOperation]] = None,
        down_operations: Optional[List[MigrationOperation]] = None,
    ) -> str:
        """Create a new migration file."""
        # Generate version (timestamp)
        version = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create migration script
        migration = MigrationScript(
            version=version,
            name=name,
            description=description,
            up_operations=up_operations or [],
            down_operations=down_operations or [],
            created_at=datetime.now(),
            checksum="",
        )

        # Calculate checksum
        migration.checksum = self._calculate_checksum(migration)

        # Save migration to file
        migration_file = self._get_migration_file_path(version, name)
        await self._save_migration_file(migration, migration_file)

        logger.info(f"Migration created: {migration_file}")
        return version

    async def apply_migrations(self, target_version: Optional[str] = None) -> List[str]:
        """Apply pending migrations up to target version."""
        await self.initialize()

        # Get pending migrations
        pending = await self.get_pending_migrations()

        if target_version:
            # Filter to target version
            pending = [m for m in pending if m.version <= target_version]

        if not pending:
            logger.info("No pending migrations to apply")
            return []

        applied = []
        manager = await get_connection_manager()

        async with manager.get_database() as db:
            runner = MigrationRunner(db, self.tenant_id)
            migrations_collection = db[self.migrations_collection_name]

            for migration in pending:
                try:
                    # Execute migration
                    execution_time = await runner.execute_migration(migration, "up")

                    # Record migration as applied
                    migration_record = {
                        "version": migration.version,
                        "name": migration.name,
                        "description": migration.description,
                        "checksum": migration.checksum,
                        "applied_at": datetime.now(),
                        "execution_time_ms": execution_time,
                        "tenant_id": self.tenant_id,
                    }

                    await migrations_collection.insert_one(migration_record)
                    applied.append(migration.version)

                    logger.info(
                        f"Applied migration {migration.version}: {migration.name}"
                    )

                except Exception as e:
                    logger.error(
                        f"Failed to apply migration {migration.version}: {str(e)}"
                    )
                    raise MigrationError(
                        f"Migration {migration.version} failed: {str(e)}"
                    )

        logger.info(f"Applied {len(applied)} migrations: {applied}")
        return applied

    async def rollback_migration(self, target_version: str) -> List[str]:
        """Rollback migrations to target version."""
        await self.initialize()

        # Get applied migrations that need to be rolled back
        applied = await self.get_applied_migrations()
        to_rollback = [m for m in applied if m.version > target_version]
        to_rollback.sort(
            key=lambda x: x.version, reverse=True
        )  # Rollback in reverse order

        if not to_rollback:
            logger.info(f"No migrations to rollback to version {target_version}")
            return []

        rolled_back = []
        manager = await get_connection_manager()

        async with manager.get_database() as db:
            runner = MigrationRunner(db, self.tenant_id)
            migrations_collection = db[self.migrations_collection_name]

            for migration_info in to_rollback:
                try:
                    # Load migration script
                    migration = await self._load_migration_script(
                        migration_info.version
                    )

                    # Execute rollback
                    execution_time = await runner.execute_migration(migration, "down")

                    # Remove migration record
                    await migrations_collection.delete_one(
                        {"version": migration_info.version}
                    )
                    rolled_back.append(migration_info.version)

                    logger.info(
                        f"Rolled back migration {migration_info.version}: {migration_info.name}"
                    )

                except Exception as e:
                    logger.error(
                        f"Failed to rollback migration {migration_info.version}: {str(e)}"
                    )
                    raise MigrationError(
                        f"Rollback {migration_info.version} failed: {str(e)}"
                    )

        logger.info(f"Rolled back {len(rolled_back)} migrations: {rolled_back}")
        return rolled_back

    async def get_migration_status(self) -> Dict[str, Any]:
        """Get comprehensive migration status."""
        await self.initialize()

        applied = await self.get_applied_migrations()
        pending = await self.get_pending_migrations()

        return {
            "database_name": self.database_name,
            "tenant_id": self.tenant_id,
            "applied_count": len(applied),
            "pending_count": len(pending),
            "latest_applied": applied[-1].version if applied else None,
            "next_pending": pending[0].version if pending else None,
            "applied_migrations": [
                {
                    "version": m.version,
                    "name": m.name,
                    "applied_at": m.applied_at.isoformat() if m.applied_at else None,
                    "execution_time_ms": m.execution_time_ms,
                }
                for m in applied
            ],
            "pending_migrations": [
                {
                    "version": m.version,
                    "name": m.name,
                    "description": m.description,
                    "created_at": m.created_at.isoformat(),
                }
                for m in pending
            ],
        }

    async def get_applied_migrations(self) -> List[MigrationInfo]:
        """Get list of applied migrations."""
        manager = await get_connection_manager()
        applied = []

        async with manager.get_database() as db:
            migrations_collection = db[self.migrations_collection_name]

            # Query for applied migrations
            query = (
                {"tenant_id": self.tenant_id}
                if self.tenant_id
                else {"tenant_id": {"$exists": False}}
            )

            cursor = migrations_collection.find(query).sort("version", 1)
            async for record in cursor:
                applied.append(
                    MigrationInfo(
                        version=record["version"],
                        name=record["name"],
                        description=record.get("description", ""),
                        created_at=record.get("created_at", datetime.now()),
                        applied_at=record.get("applied_at"),
                        checksum=record.get("checksum", ""),
                        execution_time_ms=record.get("execution_time_ms", 0),
                    )
                )

        return applied

    async def get_pending_migrations(self) -> List[MigrationScript]:
        """Get list of pending migrations."""
        applied = await self.get_applied_migrations()
        applied_versions = {m.version for m in applied}

        # Load all migration files
        all_migrations = await self._load_all_migration_files()

        # Filter out applied ones
        pending = [m for m in all_migrations if m.version not in applied_versions]
        pending.sort(key=lambda x: x.version)

        return pending

    async def validate_migrations(self) -> Dict[str, Any]:
        """Validate migration integrity."""
        issues = []
        applied = await self.get_applied_migrations()

        for migration_info in applied:
            try:
                # Load migration file
                migration = await self._load_migration_script(migration_info.version)

                # Check checksum
                current_checksum = self._calculate_checksum(migration)
                if current_checksum != migration_info.checksum:
                    issues.append(
                        {
                            "version": migration_info.version,
                            "type": "checksum_mismatch",
                            "message": f"Migration {migration_info.version} checksum mismatch",
                        }
                    )

            except FileNotFoundError:
                issues.append(
                    {
                        "version": migration_info.version,
                        "type": "missing_file",
                        "message": f"Migration file for {migration_info.version} not found",
                    }
                )
            except Exception as e:
                issues.append(
                    {
                        "version": migration_info.version,
                        "type": "load_error",
                        "message": f"Error loading migration {migration_info.version}: {str(e)}",
                    }
                )

        return {
            "valid": len(issues) == 0,
            "issues_count": len(issues),
            "issues": issues,
            "checked_migrations": len(applied),
        }

    def _get_migration_file_path(self, version: str, name: str) -> Path:
        """Get migration file path."""
        filename = f"{version}_{name.lower().replace(' ', '_')}.py"

        if self.tenant_id and self.tenant_migrations_dir:
            return self.tenant_migrations_dir / filename
        else:
            return self.migrations_dir / filename

    async def _save_migration_file(
        self, migration: MigrationScript, file_path: Path
    ) -> None:
        """Save migration to Python file."""
        # Convert operations to Python code
        up_operations_code = self._operations_to_python_code(migration.up_operations)
        down_operations_code = self._operations_to_python_code(
            migration.down_operations
        )

        content = f'''"""
Migration {migration.version}: {migration.name}

{migration.description}

Created: {migration.created_at.isoformat()}
Checksum: {migration.checksum}
"""

from datetime import datetime
from core.database.migrations import MigrationOperation

# Migration metadata
VERSION = "{migration.version}"
NAME = "{migration.name}"
DESCRIPTION = """{migration.description}"""
CREATED_AT = datetime.fromisoformat("{migration.created_at.isoformat()}")

def get_up_operations():
    """Forward migration operations."""
    return [
{up_operations_code}
    ]

def get_down_operations():
    """Backward migration operations."""
    return [
{down_operations_code}
    ]
'''

        with open(file_path, "w") as f:
            f.write(content)

    def _operations_to_python_code(self, operations: List[MigrationOperation]) -> str:
        """Convert operations to Python code."""
        if not operations:
            return ""

        lines = []
        for op in operations:
            lines.append(f"        MigrationOperation(")
            lines.append(f'            operation_type="{op.operation_type}",')
            lines.append(f'            collection_name="{op.collection_name}",')
            lines.append(f"            operation_data={repr(op.operation_data)},")
            lines.append(f"            reversible={op.reversible}")
            lines.append("        ),")

        return "\n".join(lines)

    async def _load_all_migration_files(self) -> List[MigrationScript]:
        """Load all migration files."""
        migrations = []

        # Get migration directory
        migration_dir = (
            self.tenant_migrations_dir if self.tenant_id else self.migrations_dir
        )

        if not migration_dir.exists():
            return migrations

        # Load all Python migration files
        for file_path in migration_dir.glob("*.py"):
            if file_path.name.startswith("__"):
                continue

            try:
                migration = await self._load_migration_file(file_path)
                migrations.append(migration)
            except Exception as e:
                logger.error(f"Error loading migration file {file_path}: {str(e)}")

        return migrations

    async def _load_migration_file(self, file_path: Path) -> MigrationScript:
        """Load migration from file."""
        # Dynamic import of migration module
        import importlib.util
        import sys

        spec = importlib.util.spec_from_file_location("migration", file_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Extract migration data
        migration = MigrationScript(
            version=module.VERSION,
            name=module.NAME,
            description=module.DESCRIPTION,
            up_operations=module.get_up_operations(),
            down_operations=module.get_down_operations(),
            created_at=module.CREATED_AT,
            checksum="",
        )

        # Calculate checksum
        migration.checksum = self._calculate_checksum(migration)

        return migration

    async def _load_migration_script(self, version: str) -> MigrationScript:
        """Load specific migration script by version."""
        migration_dir = (
            self.tenant_migrations_dir if self.tenant_id else self.migrations_dir
        )

        # Find migration file by version
        for file_path in migration_dir.glob(f"{version}_*.py"):
            return await self._load_migration_file(file_path)

        raise FileNotFoundError(f"Migration file for version {version} not found")

    def _calculate_checksum(self, migration: MigrationScript) -> str:
        """Calculate migration checksum."""
        # Create a stable representation of the migration
        data = {
            "version": migration.version,
            "name": migration.name,
            "description": migration.description,
            "up_operations": [asdict(op) for op in migration.up_operations],
            "down_operations": [asdict(op) for op in migration.down_operations],
        }

        # Calculate SHA256 checksum
        content = json.dumps(data, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()


# Convenience functions
async def get_migration_manager(tenant_id: Optional[str] = None) -> MigrationManager:
    """Get migration manager instance."""
    return MigrationManager(tenant_id=tenant_id)


async def apply_migrations(
    tenant_id: Optional[str] = None, target_version: Optional[str] = None
) -> List[str]:
    """Apply pending migrations - convenience function."""
    manager = await get_migration_manager(tenant_id)
    return await manager.apply_migrations(target_version)


async def rollback_to_version(
    target_version: str, tenant_id: Optional[str] = None
) -> List[str]:
    """Rollback to specific version - convenience function."""
    manager = await get_migration_manager(tenant_id)
    return await manager.rollback_migration(target_version)


async def get_migration_status(tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """Get migration status - convenience function."""
    manager = await get_migration_manager(tenant_id)
    return await manager.get_migration_status()


async def create_migration(
    name: str,
    description: str = "",
    up_operations: Optional[List[MigrationOperation]] = None,
    down_operations: Optional[List[MigrationOperation]] = None,
    tenant_id: Optional[str] = None,
) -> str:
    """Create new migration - convenience function."""
    manager = await get_migration_manager(tenant_id)
    return await manager.create_migration(
        name, description, up_operations, down_operations
    )


# Export all classes and functions
__all__ = [
    # Data Classes
    "MigrationInfo",
    "MigrationOperation",
    "MigrationScript",
    # Core Classes
    "MigrationRunner",
    "MigrationManager",
    # Convenience Functions
    "get_migration_manager",
    "apply_migrations",
    "rollback_to_version",
    "get_migration_status",
    "create_migration",
]
