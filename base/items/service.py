"""Item service — CRUD on tenant-scoped items collection."""

from datetime import datetime, timezone
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase
from fastapi import HTTPException, status
from bson import ObjectId

from base.tenant import get_tenant_collection
from base.utils import serialize_mongo_doc


class ItemService:
    def __init__(self, db: AsyncIOMotorDatabase, org_slug: str):
        self.db = db
        self.org_slug = org_slug
        self.items = get_tenant_collection(db, org_slug, "items")

    async def create_item(self, data: dict, created_by: str | None = None) -> dict:
        """Create a new item/product. Checks for duplicate SKU and barcode."""
        # Check duplicate SKU (if provided)
        if data.get("sku"):
            existing = await self.items.find_one(
                {"sku": data["sku"], "is_deleted": {"$ne": True}}
            )
            if existing:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Item with SKU '{data['sku']}' already exists",
                )

        # Check duplicate barcode (if provided)
        if data.get("barcode"):
            existing = await self.items.find_one(
                {"barcode": data["barcode"], "is_deleted": {"$ne": True}}
            )
            if existing:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Item with barcode '{data['barcode']}' already exists",
                )

        now = datetime.now(timezone.utc)

        # Flatten nested models to dicts for MongoDB
        item_doc = {
            **data,
            "pricing": data.get("pricing") if isinstance(data.get("pricing"), dict) else (data["pricing"] if data.get("pricing") else None),
            "dimensions": data.get("dimensions") if isinstance(data.get("dimensions"), dict) else None,
            "stock": data.get("stock") if isinstance(data.get("stock"), dict) else {"current_stock": 0},
            "suppliers": data.get("suppliers", []),
            "is_deleted": False,
            "created_by": created_by,
            "created_at": now,
            "updated_at": now,
        }

        result = await self.items.insert_one(item_doc)
        item_doc["_id"] = result.inserted_id
        return serialize_mongo_doc(item_doc)

    async def get_item(self, item_id: str) -> dict:
        """Get a single item by ID."""
        if not ObjectId.is_valid(item_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid item ID",
            )
        item = await self.items.find_one(
            {"_id": ObjectId(item_id), "is_deleted": {"$ne": True}}
        )
        if not item:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Item not found"
            )
        return serialize_mongo_doc(item)

    async def list_items(
        self,
        query: Optional[str] = None,
        category: Optional[str] = None,
        status_filter: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        """List items with search (name, SKU, barcode, brand, tags) and category/status filters."""
        filters: dict = {"is_deleted": {"$ne": True}}

        if query:
            filters["$or"] = [
                {"name": {"$regex": query, "$options": "i"}},
                {"sku": {"$regex": query, "$options": "i"}},
                {"barcode": {"$regex": query, "$options": "i"}},
                {"brand": {"$regex": query, "$options": "i"}},
                {"tags": {"$regex": query, "$options": "i"}},
                {"description": {"$regex": query, "$options": "i"}},
            ]

        if category:
            filters["category"] = category

        if status_filter:
            filters["status"] = status_filter

        total = await self.items.count_documents(filters)
        cursor = (
            self.items.find(filters)
            .skip(offset)
            .limit(limit)
            .sort("created_at", -1)
        )
        items = []
        async for doc in cursor:
            items.append(serialize_mongo_doc(doc))

        return items, total

    async def update_item(self, item_id: str, update_data: dict) -> dict:
        """Update item fields. Only non-None fields are updated."""
        if not ObjectId.is_valid(item_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid item ID",
            )

        update_data["updated_at"] = datetime.now(timezone.utc)
        clean = {k: v for k, v in update_data.items() if v is not None}

        result = await self.items.find_one_and_update(
            {"_id": ObjectId(item_id), "is_deleted": {"$ne": True}},
            {"$set": clean},
            return_document=True,
        )
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Item not found"
            )
        return serialize_mongo_doc(result)

    async def delete_item(self, item_id: str) -> dict:
        """Soft-delete an item (sets is_deleted=True, preserves data)."""
        if not ObjectId.is_valid(item_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid item ID",
            )
        result = await self.items.update_one(
            {"_id": ObjectId(item_id), "is_deleted": {"$ne": True}},
            {"$set": {"is_deleted": True, "deleted_at": datetime.now(timezone.utc)}},
        )
        if result.modified_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Item not found or already deleted",
            )
        return {"message": "Item deleted successfully"}
