"""
Audit Service — log and query audit trail entries.

Collection: {slug}_audit_logs (tenant-scoped)

Usage from other services:
    audit = AuditService(db, org_slug)
    await audit.log(
        module="items",
        action="update",
        user_id="...", user_email="...", user_role="admin",
        resource_id="item_id_here",
        description="Updated item 'JK Cement 50kg'",
        before=old_doc, after=new_doc,
        ip_address="127.0.0.1",
        http_method="PUT", endpoint="/api/v1/items/xxx"
    )
"""

from datetime import datetime, timezone
from typing import Optional, Any

from motor.motor_asyncio import AsyncIOMotorDatabase
from fastapi import HTTPException
from bson import ObjectId

from base.tenant import get_tenant_collection
from base.utils import serialize_mongo_doc


def _diff_fields(before: dict | None, after: dict | None) -> list[str]:
    """
    Compare two dicts and return a list of field names that changed.
    Ignores metadata fields like _id, updated_at, created_at.
    """
    if not before or not after:
        return []

    skip = {"_id", "updated_at", "created_at", "created_by"}
    changed = []

    all_keys = set(before.keys()) | set(after.keys())
    for key in all_keys:
        if key in skip:
            continue
        if before.get(key) != after.get(key):
            changed.append(key)
    return changed


class AuditService:
    def __init__(self, db: AsyncIOMotorDatabase, org_slug: str):
        self.db = db
        self.org_slug = org_slug
        self.logs = get_tenant_collection(db, org_slug, "audit_logs")

    async def log(
        self,
        module: str,
        action: str,
        user_id: str | None = None,
        user_email: str | None = None,
        user_role: str | None = None,
        resource_id: str | None = None,
        description: str = "",
        before: dict | Any = None,
        after: dict | Any = None,
        ip_address: str | None = None,
        http_method: str | None = None,
        endpoint: str | None = None,
    ) -> dict:
        """
        Record an audit log entry. Call this from any service after a
        create/update/delete operation.

        Args:
            module: Which module (items, users, pos, etc.)
            action: What happened (create, update, delete, login, etc.)
            user_id: Who did it
            resource_id: ID of the affected document
            description: Human-readable summary
            before: Document snapshot before the change (for updates)
            after: Document snapshot after the change
            ip_address: Client IP
        """
        # Serialize before/after if they're mongo docs
        if before and isinstance(before, dict) and "_id" in before:
            before = serialize_mongo_doc(before)
        if after and isinstance(after, dict) and "_id" in after:
            after = serialize_mongo_doc(after)

        # Calculate changed fields
        changed_fields = _diff_fields(before, after) if before and after else None

        entry = {
            "module": module,
            "action": action,
            "user_id": user_id,
            "user_email": user_email,
            "user_role": user_role,
            "resource_id": resource_id,
            "description": description,
            "before": before,
            "after": after,
            "changed_fields": changed_fields,
            "ip_address": ip_address,
            "http_method": http_method,
            "endpoint": endpoint,
            "timestamp": datetime.now(timezone.utc),
        }

        result = await self.logs.insert_one(entry)
        entry["_id"] = result.inserted_id
        return serialize_mongo_doc(entry)

    async def list_logs(
        self,
        module: str | None = None,
        action: str | None = None,
        user_id: str | None = None,
        resource_id: str | None = None,
        from_date: datetime | None = None,
        to_date: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        """
        Query audit logs with optional filters.
        Results sorted by most recent first.
        """
        filters: dict = {}

        if module:
            filters["module"] = module
        if action:
            filters["action"] = action
        if user_id:
            filters["user_id"] = user_id
        if resource_id:
            filters["resource_id"] = resource_id
        if from_date or to_date:
            date_filter = {}
            if from_date:
                date_filter["$gte"] = from_date
            if to_date:
                date_filter["$lte"] = to_date
            filters["timestamp"] = date_filter

        total = await self.logs.count_documents(filters)
        cursor = (
            self.logs.find(filters)
            .skip(offset)
            .limit(limit)
            .sort("timestamp", -1)
        )
        docs = [serialize_mongo_doc(d) async for d in cursor]
        return docs, total

    async def get_log(self, log_id: str) -> dict:
        """Get a single audit log entry by ID (with full before/after data)."""
        if not ObjectId.is_valid(log_id):
            raise HTTPException(status_code=400, detail="Invalid audit log ID")
        doc = await self.logs.find_one({"_id": ObjectId(log_id)})
        if not doc:
            raise HTTPException(status_code=404, detail="Audit log not found")
        return serialize_mongo_doc(doc)

    async def get_resource_history(
        self, resource_id: str, limit: int = 20
    ) -> list[dict]:
        """
        Get the complete audit history for a specific resource (item, user, etc.).
        Shows all changes made to that resource over time.
        """
        cursor = (
            self.logs.find({"resource_id": resource_id})
            .limit(limit)
            .sort("timestamp", -1)
        )
        return [serialize_mongo_doc(d) async for d in cursor]
