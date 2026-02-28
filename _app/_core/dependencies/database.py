"""
Database dependencies for FastAPI
"""
import logging
from typing import AsyncGenerator, Dict, Any
from fastapi import Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorCollection
from pymongo.errors import ServerSelectionTimeoutError

from ..database import get_database, get_session_manager, SessionManager
from ..config import get_settings

logger = logging.getLogger(__name__)


async def get_db() -> AsyncIOMotorDatabase:
    """
    Get database connection
    """
    try:
        db = await get_database()
        return db
    except ServerSelectionTimeoutError:
        logger.error("Database connection timeout")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable"
        )
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database connection failed"
        )


async def get_session() -> AsyncGenerator[Dict[str, Any], None]:
    """
    Get database session with transaction support
    """
    session_manager = await get_session_manager()
    async with session_manager.session() as session:
        yield session


async def get_collection(collection_name: str, db: AsyncIOMotorDatabase = Depends(get_db)) -> AsyncIOMotorCollection:
    """
    Get specific collection
    """
    return db[collection_name]


# Common collection dependencies
async def get_users_collection(db: AsyncIOMotorDatabase = Depends(get_db)) -> AsyncIOMotorCollection:
    """Get users collection"""
    return db.users


async def get_tenants_collection(db: AsyncIOMotorDatabase = Depends(get_db)) -> AsyncIOMotorCollection:
    """Get tenants collection"""
    return db.tenants


async def get_stores_collection(db: AsyncIOMotorDatabase = Depends(get_db)) -> AsyncIOMotorCollection:
    """Get stores collection"""
    return db.stores


async def get_employees_collection(db: AsyncIOMotorDatabase = Depends(get_db)) -> AsyncIOMotorCollection:
    """Get employees collection"""
    return db.employees


async def get_products_collection(db: AsyncIOMotorDatabase = Depends(get_db)) -> AsyncIOMotorCollection:
    """Get products collection"""
    return db.products


async def get_inventory_collection(db: AsyncIOMotorDatabase = Depends(get_db)) -> AsyncIOMotorCollection:
    """Get inventory collection"""
    return db.inventory


async def get_transactions_collection(db: AsyncIOMotorDatabase = Depends(get_db)) -> AsyncIOMotorCollection:
    """Get transactions collection"""
    return db.transactions


async def get_audit_logs_collection(db: AsyncIOMotorDatabase = Depends(get_db)) -> AsyncIOMotorCollection:
    """Get audit logs collection"""
    return db.audit_logs


class TenantDatabase:
    """
    Dependency class for tenant-specific database operations
    """

    def __init__(self, tenant_param: str = "tenant_id"):
        self.tenant_param = tenant_param

    async def __call__(
        self,
        tenant_id: str,
        db: AsyncIOMotorDatabase = Depends(get_db)
    ) -> AsyncIOMotorDatabase:
        # In a true multi-tenant setup, you might switch databases here
        # For now, we'll just return the same db but could add tenant filtering
        return db


# Database health check dependency
async def check_db_health(db: AsyncIOMotorDatabase = Depends(get_db)) -> Dict[str, Any]:
    """
    Check database health
    """
    try:
        # Simple ping to check connectivity
        await db.command("ping")
        return {"status": "healthy", "database": db.name}
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database health check failed"
        )


# Pagination dependency
class Pagination:
    def __init__(self, skip: int = 0, limit: int = 100):
        self.skip = max(0, skip)
        self.limit = min(1000, max(1, limit))  # Cap at 1000 items

    def apply_to_cursor(self, cursor):
        return cursor.skip(self.skip).limit(self.limit)


def get_pagination(skip: int = 0, limit: int = 100) -> Pagination:
    """Get pagination parameters"""
    return Pagination(skip, limit)


# Search and filtering
class SearchFilter:
    def __init__(self, search: str = None, sort_by: str = None, sort_order: int = 1):
        self.search = search
        self.sort_by = sort_by or "_id"
        self.sort_order = sort_order if sort_order in [1, -1] else 1

    def build_search_query(self, search_fields: list) -> Dict[str, Any]:
        if not self.search:
            return {}

        # Build text search query
        return {
            "$or": [
                {field: {"$regex": self.search, "$options": "i"}}
                for field in search_fields
            ]
        }

    def build_sort(self) -> list:
        return [(self.sort_by, self.sort_order)]


def get_search_filter(search: str = None, sort_by: str = None, sort_order: int = 1) -> SearchFilter:
    """Get search and filter parameters"""
    return SearchFilter(search, sort_by, sort_order)


# Tenant-specific collection dependencies
tenant_db = TenantDatabase()