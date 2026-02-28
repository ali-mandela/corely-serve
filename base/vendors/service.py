"""Vendor service — CRUD on tenant-scoped vendors collection."""

from datetime import datetime, timezone
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase
from fastapi import HTTPException, status
from bson import ObjectId

from base.tenant import get_tenant_collection
from base.utils import serialize_mongo_doc


class VendorService:
    def __init__(self, db: AsyncIOMotorDatabase, org_slug: str):
        self.db = db
        self.org_slug = org_slug
        self.vendors = get_tenant_collection(db, org_slug, "vendors")

    async def create_vendor(self, data: dict, created_by: str | None = None) -> dict:
        """Create a new vendor/supplier. Checks for duplicate phone or GSTIN."""
        # Duplicate check on phone or GSTIN
        or_filters = [{"phone": data["phone"]}]
        if data.get("gstin"):
            or_filters.append({"gstin": data["gstin"]})

        existing = await self.vendors.find_one(
            {"$or": or_filters, "is_deleted": {"$ne": True}}
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Vendor with this phone or GSTIN already exists",
            )

        now = datetime.now(timezone.utc)
        doc = {
            **data,
            "is_deleted": False,
            "created_by": created_by,
            "created_at": now,
            "updated_at": now,
        }
        result = await self.vendors.insert_one(doc)
        doc["_id"] = result.inserted_id
        return serialize_mongo_doc(doc)

    async def get_vendor(self, vendor_id: str) -> dict:
        """Get a single vendor by ID."""
        if not ObjectId.is_valid(vendor_id):
            raise HTTPException(status_code=400, detail="Invalid vendor ID")
        doc = await self.vendors.find_one(
            {"_id": ObjectId(vendor_id), "is_deleted": {"$ne": True}}
        )
        if not doc:
            raise HTTPException(status_code=404, detail="Vendor not found")
        return serialize_mongo_doc(doc)

    async def list_vendors(
        self,
        query: Optional[str] = None,
        vendor_type: Optional[str] = None,
        status_filter: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        """List vendors with search (name, phone, email, GSTIN, categories) and type/status filter."""
        filters: dict = {"is_deleted": {"$ne": True}}
        if query:
            filters["$or"] = [
                {"name": {"$regex": query, "$options": "i"}},
                {"display_name": {"$regex": query, "$options": "i"}},
                {"phone": {"$regex": query, "$options": "i"}},
                {"email": {"$regex": query, "$options": "i"}},
                {"gstin": {"$regex": query, "$options": "i"}},
                {"categories_supplied": {"$regex": query, "$options": "i"}},
            ]
        if vendor_type:
            filters["vendor_type"] = vendor_type
        if status_filter:
            filters["status"] = status_filter

        total = await self.vendors.count_documents(filters)
        cursor = self.vendors.find(filters).skip(offset).limit(limit).sort("created_at", -1)
        docs = [serialize_mongo_doc(d) async for d in cursor]
        return docs, total

    async def update_vendor(self, vendor_id: str, update_data: dict) -> dict:
        """Update vendor fields. Only non-None fields are updated."""
        if not ObjectId.is_valid(vendor_id):
            raise HTTPException(status_code=400, detail="Invalid vendor ID")
        update_data["updated_at"] = datetime.now(timezone.utc)
        clean = {k: v for k, v in update_data.items() if v is not None}
        result = await self.vendors.find_one_and_update(
            {"_id": ObjectId(vendor_id), "is_deleted": {"$ne": True}},
            {"$set": clean},
            return_document=True,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Vendor not found")
        return serialize_mongo_doc(result)

    async def delete_vendor(self, vendor_id: str) -> dict:
        """Soft-delete a vendor (sets is_deleted=True)."""
        if not ObjectId.is_valid(vendor_id):
            raise HTTPException(status_code=400, detail="Invalid vendor ID")
        result = await self.vendors.update_one(
            {"_id": ObjectId(vendor_id), "is_deleted": {"$ne": True}},
            {"$set": {"is_deleted": True, "deleted_at": datetime.now(timezone.utc)}},
        )
        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Vendor not found or already deleted")
        return {"message": "Vendor deleted successfully"}
