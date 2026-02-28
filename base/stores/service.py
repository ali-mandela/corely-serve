"""
Stores Service — manage locations/branches and inter-store stock transfers.

Collections (tenant-scoped):
    - {slug}_stores           : Store / branch / godown records
    - {slug}_stock_transfers  : Transfer records between locations
    - {slug}_stock_movements  : Auto-created transfer_out / transfer_in movements
    - {slug}_items            : Stock levels updated on transfer
"""

from datetime import datetime, timezone
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase
from fastapi import HTTPException
from bson import ObjectId

from base.tenant import get_tenant_collection
from base.utils import serialize_mongo_doc


class StoresService:
    def __init__(self, db: AsyncIOMotorDatabase, org_slug: str):
        self.db = db
        self.org_slug = org_slug
        self.stores = get_tenant_collection(db, org_slug, "stores")
        self.transfers = get_tenant_collection(db, org_slug, "stock_transfers")
        self.movements = get_tenant_collection(db, org_slug, "stock_movements")
        self.items = get_tenant_collection(db, org_slug, "items")

    # ── Store CRUD ───────────────────────────────────────────────

    async def create_store(self, data: dict, created_by: str | None = None) -> dict:
        """
        Create a new store/branch/godown.
        Validates that the store code is unique within the tenant.
        """
        # Check unique code
        existing = await self.stores.find_one({
            "code": data.get("code"),
            "is_deleted": {"$ne": True},
        })
        if existing:
            raise HTTPException(status_code=409, detail=f"Store code '{data['code']}' already exists")

        now = datetime.now(timezone.utc)
        doc = {
            **data,
            "is_deleted": False,
            "created_by": created_by,
            "created_at": now,
            "updated_at": now,
        }

        # If is_default, unset default on all other stores
        if data.get("is_default"):
            await self.stores.update_many(
                {"is_deleted": {"$ne": True}},
                {"$set": {"is_default": False}},
            )

        result = await self.stores.insert_one(doc)
        doc["_id"] = result.inserted_id
        return serialize_mongo_doc(doc)

    async def get_store(self, store_id: str) -> dict:
        """Get a single store by ID."""
        if not ObjectId.is_valid(store_id):
            raise HTTPException(status_code=400, detail="Invalid store ID")
        doc = await self.stores.find_one(
            {"_id": ObjectId(store_id), "is_deleted": {"$ne": True}}
        )
        if not doc:
            raise HTTPException(status_code=404, detail="Store not found")
        return serialize_mongo_doc(doc)

    async def list_stores(
        self,
        store_type: str | None = None,
        status_filter: str | None = None,
        query: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        """List stores with optional filters."""
        filters: dict = {"is_deleted": {"$ne": True}}

        if store_type:
            filters["store_type"] = store_type
        if status_filter:
            filters["status"] = status_filter
        if query:
            filters["$or"] = [
                {"name": {"$regex": query, "$options": "i"}},
                {"code": {"$regex": query, "$options": "i"}},
                {"address.city": {"$regex": query, "$options": "i"}},
            ]

        total = await self.stores.count_documents(filters)
        cursor = self.stores.find(filters).skip(offset).limit(limit).sort("created_at", -1)
        docs = [serialize_mongo_doc(d) async for d in cursor]
        return docs, total

    async def update_store(self, store_id: str, update_data: dict) -> dict:
        """Update a store's details."""
        if not ObjectId.is_valid(store_id):
            raise HTTPException(status_code=400, detail="Invalid store ID")

        update_data["updated_at"] = datetime.now(timezone.utc)
        clean = {k: v for k, v in update_data.items() if v is not None}

        # If setting as default, unset others first
        if clean.get("is_default"):
            await self.stores.update_many(
                {"is_deleted": {"$ne": True}},
                {"$set": {"is_default": False}},
            )

        result = await self.stores.find_one_and_update(
            {"_id": ObjectId(store_id), "is_deleted": {"$ne": True}},
            {"$set": clean},
            return_document=True,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Store not found")
        return serialize_mongo_doc(result)

    async def delete_store(self, store_id: str) -> dict:
        """Soft delete a store."""
        if not ObjectId.is_valid(store_id):
            raise HTTPException(status_code=400, detail="Invalid store ID")

        result = await self.stores.find_one_and_update(
            {"_id": ObjectId(store_id), "is_deleted": {"$ne": True}},
            {"$set": {"is_deleted": True, "deleted_at": datetime.now(timezone.utc)}},
            return_document=True,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Store not found")
        return serialize_mongo_doc(result)

    # ── Stock Transfers ──────────────────────────────────────────

    async def create_transfer(self, data: dict, created_by: str | None = None) -> dict:
        """
        Initiate a stock transfer between two stores.

        Flow:
            1. Validate source and destination stores exist
            2. Create transfer record with status 'pending'
            3. Stock is NOT deducted yet (deducted on dispatch)
        """
        from_id = data.get("from_store_id")
        to_id = data.get("to_store_id")

        if from_id == to_id:
            raise HTTPException(status_code=400, detail="Source and destination must be different")

        # Validate both stores exist
        for sid, label in [(from_id, "Source"), (to_id, "Destination")]:
            if not ObjectId.is_valid(sid):
                raise HTTPException(status_code=400, detail=f"Invalid {label} store ID")
            store = await self.stores.find_one({"_id": ObjectId(sid), "is_deleted": {"$ne": True}})
            if not store:
                raise HTTPException(status_code=404, detail=f"{label} store not found")

        now = datetime.now(timezone.utc)

        # Generate transfer number
        transfer_number = await self._generate_transfer_number()

        doc = {
            **data,
            "transfer_number": transfer_number,
            "status": "pending",
            "created_by": created_by,
            "created_at": now,
            "updated_at": now,
        }

        result = await self.transfers.insert_one(doc)
        doc["_id"] = result.inserted_id
        return serialize_mongo_doc(doc)

    async def dispatch_transfer(self, transfer_id: str, dispatched_by: str | None = None) -> dict:
        """
        Mark transfer as in_transit — deducts stock from source store.
        Creates transfer_out movements for each item.
        """
        if not ObjectId.is_valid(transfer_id):
            raise HTTPException(status_code=400, detail="Invalid transfer ID")

        transfer = await self.transfers.find_one(
            {"_id": ObjectId(transfer_id), "status": "pending"}
        )
        if not transfer:
            raise HTTPException(status_code=404, detail="Pending transfer not found")

        now = datetime.now(timezone.utc)
        tid = str(transfer["_id"])

        # Create transfer_out movements and deduct stock
        for item in transfer.get("items", []):
            movement = {
                "item_id": item["item_id"],
                "item_name": item.get("item_name"),
                "movement_type": "transfer_out",
                "quantity": item["quantity"],
                "unit": item.get("unit", "pcs"),
                "unit_cost": item.get("unit_cost"),
                "reference_type": "stock_transfer",
                "reference_id": tid,
                "location_from": transfer.get("from_store_id"),
                "location_to": transfer.get("to_store_id"),
                "created_by": dispatched_by,
                "created_at": now,
            }
            await self.movements.insert_one(movement)

            # Deduct from source
            await self.items.update_one(
                {"_id": ObjectId(item["item_id"])},
                {"$inc": {"stock.current_stock": -item["quantity"]}},
            )

        result = await self.transfers.find_one_and_update(
            {"_id": ObjectId(transfer_id)},
            {"$set": {"status": "in_transit", "dispatched_at": now, "dispatched_by": dispatched_by, "updated_at": now}},
            return_document=True,
        )
        return serialize_mongo_doc(result)

    async def receive_transfer(
        self, transfer_id: str, receive_data: dict, received_by: str | None = None
    ) -> dict:
        """
        Mark transfer as received — adds stock at destination store.
        Creates transfer_in movements for each item.
        """
        if not ObjectId.is_valid(transfer_id):
            raise HTTPException(status_code=400, detail="Invalid transfer ID")

        transfer = await self.transfers.find_one(
            {"_id": ObjectId(transfer_id), "status": "in_transit"}
        )
        if not transfer:
            raise HTTPException(status_code=404, detail="In-transit transfer not found")

        now = datetime.now(timezone.utc)
        tid = str(transfer["_id"])

        # Use received_items if partial, otherwise use original items
        items_received = receive_data.get("received_items") or transfer.get("items", [])

        for item in items_received:
            movement = {
                "item_id": item["item_id"],
                "item_name": item.get("item_name"),
                "movement_type": "transfer_in",
                "quantity": item["quantity"],
                "unit": item.get("unit", "pcs"),
                "unit_cost": item.get("unit_cost"),
                "reference_type": "stock_transfer",
                "reference_id": tid,
                "location_from": transfer.get("from_store_id"),
                "location_to": transfer.get("to_store_id"),
                "created_by": received_by,
                "created_at": now,
            }
            await self.movements.insert_one(movement)

            # Add to destination
            await self.items.update_one(
                {"_id": ObjectId(item["item_id"])},
                {"$inc": {"stock.current_stock": item["quantity"]}},
            )

        result = await self.transfers.find_one_and_update(
            {"_id": ObjectId(transfer_id)},
            {"$set": {
                "status": "received",
                "received_at": now,
                "received_by": received_by,
                "received_items": items_received,
                "receive_notes": receive_data.get("notes"),
                "updated_at": now,
            }},
            return_document=True,
        )
        return serialize_mongo_doc(result)

    async def cancel_transfer(self, transfer_id: str) -> dict:
        """Cancel a pending transfer (before dispatch)."""
        if not ObjectId.is_valid(transfer_id):
            raise HTTPException(status_code=400, detail="Invalid transfer ID")

        result = await self.transfers.find_one_and_update(
            {"_id": ObjectId(transfer_id), "status": "pending"},
            {"$set": {"status": "cancelled", "cancelled_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)}},
            return_document=True,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Pending transfer not found or already dispatched")
        return serialize_mongo_doc(result)

    async def list_transfers(
        self,
        status_filter: str | None = None,
        store_id: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        """List transfers — optionally filter by status or involving a specific store."""
        filters: dict = {}

        if status_filter:
            filters["status"] = status_filter
        if store_id:
            filters["$or"] = [
                {"from_store_id": store_id},
                {"to_store_id": store_id},
            ]

        total = await self.transfers.count_documents(filters)
        cursor = self.transfers.find(filters).skip(offset).limit(limit).sort("created_at", -1)
        docs = [serialize_mongo_doc(d) async for d in cursor]
        return docs, total

    async def get_transfer(self, transfer_id: str) -> dict:
        """Get a single transfer with all details."""
        if not ObjectId.is_valid(transfer_id):
            raise HTTPException(status_code=400, detail="Invalid transfer ID")
        doc = await self.transfers.find_one({"_id": ObjectId(transfer_id)})
        if not doc:
            raise HTTPException(status_code=404, detail="Transfer not found")
        return serialize_mongo_doc(doc)

    # ── Helpers ──────────────────────────────────────────────────

    async def _generate_transfer_number(self) -> str:
        """Generate sequential transfer number: TRF-YYYYMMDD-XXXX."""
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        prefix = f"TRF-{today}-"

        last = await self.transfers.find_one(
            {"transfer_number": {"$regex": f"^{prefix}"}},
            sort=[("transfer_number", -1)],
        )
        if last:
            last_num = int(last["transfer_number"].split("-")[-1])
            return f"{prefix}{str(last_num + 1).zfill(4)}"
        return f"{prefix}0001"
