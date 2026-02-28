"""
Inventory service — stock movements, purchase entries, adjustments.

Collections used (all tenant-scoped):
  - {slug}_stock_movements   → every stock change
  - {slug}_purchase_entries   → purchase / GRN records
  - {slug}_items              → updates current_stock on items
"""

from datetime import datetime, timezone
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase
from fastapi import HTTPException, status
from bson import ObjectId

from base.tenant import get_tenant_collection
from base.utils import serialize_mongo_doc


class InventoryService:
    def __init__(self, db: AsyncIOMotorDatabase, org_slug: str):
        self.db = db
        self.org_slug = org_slug
        self.movements = get_tenant_collection(db, org_slug, "stock_movements")
        self.purchases = get_tenant_collection(db, org_slug, "purchase_entries")
        self.items = get_tenant_collection(db, org_slug, "items")

    # ── Stock movement helpers ───────────────────────────────────

    async def _update_item_stock(self, item_id: str, qty_change: float) -> None:
        """
        Update the item's current_stock by qty_change.
        Positive = stock in, Negative = stock out.
        """
        if not ObjectId.is_valid(item_id):
            return
        await self.items.update_one(
            {"_id": ObjectId(item_id)},
            {"$inc": {"stock.current_stock": qty_change}},
        )

    def _resolve_qty_change(self, movement_type: str, quantity: float) -> float:
        """Resolve whether a movement increases or decreases stock."""
        increases = {"stock_in", "return_in", "transfer_in", "opening_stock"}
        if movement_type in increases:
            return quantity
        return -quantity

    # ── Stock Movements ──────────────────────────────────────────

    async def record_movement(self, data: dict, created_by: str | None = None) -> dict:
        """Record a single stock movement and update item stock."""
        now = datetime.now(timezone.utc)

        movement_doc = {
            **data,
            "created_by": created_by,
            "created_at": now,
        }
        result = await self.movements.insert_one(movement_doc)
        movement_doc["_id"] = result.inserted_id

        # Update item stock
        qty_change = self._resolve_qty_change(data["movement_type"], data["quantity"])
        await self._update_item_stock(data["item_id"], qty_change)

        return serialize_mongo_doc(movement_doc)

    async def list_movements(
        self,
        item_id: Optional[str] = None,
        movement_type: Optional[str] = None,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        filters: dict = {}

        if item_id:
            filters["item_id"] = item_id
        if movement_type:
            filters["movement_type"] = movement_type
        if from_date or to_date:
            date_filter = {}
            if from_date:
                date_filter["$gte"] = from_date
            if to_date:
                date_filter["$lte"] = to_date
            filters["created_at"] = date_filter

        total = await self.movements.count_documents(filters)
        cursor = (
            self.movements.find(filters)
            .skip(offset)
            .limit(limit)
            .sort("created_at", -1)
        )
        docs = [serialize_mongo_doc(d) async for d in cursor]
        return docs, total

    # ── Purchase Entries ─────────────────────────────────────────

    async def create_purchase(self, data: dict, created_by: str | None = None) -> dict:
        """
        Record a purchase entry and auto-create stock_in movements
        for each line item.
        """
        now = datetime.now(timezone.utc)

        purchase_doc = {
            **data,
            "is_deleted": False,
            "created_by": created_by,
            "created_at": now,
            "updated_at": now,
        }

        result = await self.purchases.insert_one(purchase_doc)
        purchase_doc["_id"] = result.inserted_id
        purchase_id = str(result.inserted_id)

        # Auto-create stock_in movements for each line item
        for line in data.get("items", []):
            received = line.get("received_qty") or line.get("quantity", 0)
            if received > 0:
                movement = {
                    "item_id": line["item_id"],
                    "item_name": line.get("item_name"),
                    "sku": line.get("sku"),
                    "movement_type": "stock_in",
                    "quantity": received,
                    "unit": line.get("unit", "pcs"),
                    "unit_cost": line.get("unit_price"),
                    "reference_type": "purchase",
                    "reference_id": purchase_id,
                    "batch_number": line.get("batch_number"),
                    "notes": f"Purchase #{data.get('invoice_number', 'N/A')}",
                    "created_by": created_by,
                    "created_at": now,
                }
                await self.movements.insert_one(movement)
                await self._update_item_stock(line["item_id"], received)

        return serialize_mongo_doc(purchase_doc)

    async def get_purchase(self, purchase_id: str) -> dict:
        if not ObjectId.is_valid(purchase_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid purchase ID",
            )
        doc = await self.purchases.find_one(
            {"_id": ObjectId(purchase_id), "is_deleted": {"$ne": True}}
        )
        if not doc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Purchase entry not found",
            )
        return serialize_mongo_doc(doc)

    async def list_purchases(
        self,
        supplier_name: Optional[str] = None,
        status_filter: Optional[str] = None,
        payment_status: Optional[str] = None,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        filters: dict = {"is_deleted": {"$ne": True}}

        if supplier_name:
            filters["supplier.name"] = {"$regex": supplier_name, "$options": "i"}
        if status_filter:
            filters["status"] = status_filter
        if payment_status:
            filters["payment_status"] = payment_status
        if from_date or to_date:
            date_filter = {}
            if from_date:
                date_filter["$gte"] = from_date
            if to_date:
                date_filter["$lte"] = to_date
            filters["created_at"] = date_filter

        total = await self.purchases.count_documents(filters)
        cursor = (
            self.purchases.find(filters)
            .skip(offset)
            .limit(limit)
            .sort("created_at", -1)
        )
        docs = [serialize_mongo_doc(d) async for d in cursor]
        return docs, total

    # ── Stock Adjustments ────────────────────────────────────────

    async def adjust_stock(self, data: dict, created_by: str | None = None) -> dict:
        """
        Manual stock adjustment. Creates a stock movement with reason.
        """
        adj_type = data.get("adjustment_type", "increase")
        quantity = data["quantity"]
        movement_type = "stock_in" if adj_type == "increase" else "stock_out"
        qty_change = quantity if adj_type == "increase" else -quantity

        now = datetime.now(timezone.utc)

        movement = {
            "item_id": data["item_id"],
            "item_name": data.get("item_name"),
            "sku": data.get("sku"),
            "movement_type": movement_type,
            "quantity": quantity,
            "unit": data.get("unit", "pcs"),
            "reference_type": "adjustment",
            "reason": data.get("reason"),
            "notes": data.get("notes"),
            "to_location": data.get("location"),
            "created_by": created_by,
            "created_at": now,
        }
        result = await self.movements.insert_one(movement)
        movement["_id"] = result.inserted_id

        # Update item stock
        await self._update_item_stock(data["item_id"], qty_change)

        return serialize_mongo_doc(movement)

    # ── Stock Reports ────────────────────────────────────────────

    async def get_stock_summary(
        self,
        low_stock_only: bool = False,
        category: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        """
        Get current stock levels for all items.
        Optionally filter to only low-stock items.
        """
        filters: dict = {"is_deleted": {"$ne": True}}

        if category:
            filters["category"] = category

        if low_stock_only:
            # Items where current_stock <= min_stock_level
            filters["$expr"] = {
                "$lte": [
                    "$stock.current_stock",
                    {"$ifNull": ["$stock.min_stock_level", 0]},
                ]
            }

        projection = {
            "name": 1,
            "sku": 1,
            "category": 1,
            "unit": 1,
            "stock": 1,
            "pricing.selling_price": 1,
            "pricing.cost_price": 1,
            "status": 1,
        }

        total = await self.items.count_documents(filters)
        cursor = (
            self.items.find(filters, projection)
            .skip(offset)
            .limit(limit)
            .sort("name", 1)
        )
        docs = [serialize_mongo_doc(d) async for d in cursor]
        return docs, total

    async def get_item_ledger(
        self,
        item_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        """Full movement history for a single item (stock ledger)."""
        if not ObjectId.is_valid(item_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid item ID",
            )

        filters = {"item_id": item_id}
        total = await self.movements.count_documents(filters)
        cursor = (
            self.movements.find(filters)
            .skip(offset)
            .limit(limit)
            .sort("created_at", -1)
        )
        docs = [serialize_mongo_doc(d) async for d in cursor]
        return docs, total
