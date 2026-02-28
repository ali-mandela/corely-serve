"""
POS Service — sale creation, stock deduction, hold/complete, and returns.

Collections used (all tenant-scoped):
    - {slug}_sales          : Sale / bill records
    - {slug}_sale_returns   : Return / credit note records
    - {slug}_stock_movements: Auto-created stock_out on sale completion
    - {slug}_items          : Stock levels updated on sale / return
    - {slug}_customers      : Outstanding balance updated on credit sales
"""

from datetime import datetime, timezone
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase
from fastapi import HTTPException, status
from bson import ObjectId

from base.tenant import get_tenant_collection
from base.utils import serialize_mongo_doc


class POSService:
    def __init__(self, db: AsyncIOMotorDatabase, org_slug: str):
        self.db = db
        self.org_slug = org_slug
        self.sales = get_tenant_collection(db, org_slug, "sales")
        self.returns = get_tenant_collection(db, org_slug, "sale_returns")
        self.movements = get_tenant_collection(db, org_slug, "stock_movements")
        self.items = get_tenant_collection(db, org_slug, "items")

    # ── Invoice number generation ────────────────────────────────

    async def _generate_invoice_number(self) -> str:
        """
        Generate sequential invoice number: INV-YYYYMMDD-XXXX
        e.g. INV-20260301-0001, INV-20260301-0002
        """
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        prefix = f"INV-{today}-"

        last_sale = await self.sales.find_one(
            {"invoice_number": {"$regex": f"^{prefix}"}},
            sort=[("invoice_number", -1)],
        )
        if last_sale:
            last_num = int(last_sale["invoice_number"].split("-")[-1])
            return f"{prefix}{str(last_num + 1).zfill(4)}"
        return f"{prefix}0001"

    # ── Stock deduction ──────────────────────────────────────────

    async def _deduct_stock(self, sale_id: str, items: list, created_by: str | None) -> None:
        """
        Create stock_out movements for each item in the sale.
        Called when a sale is completed (not on draft/hold).
        """
        now = datetime.now(timezone.utc)
        for item in items:
            # Create stock_out movement
            movement = {
                "item_id": item["item_id"],
                "item_name": item.get("item_name"),
                "sku": item.get("sku"),
                "movement_type": "stock_out",
                "quantity": item["quantity"],
                "unit": item.get("unit", "pcs"),
                "unit_cost": item.get("unit_price"),
                "reference_type": "sale",
                "reference_id": sale_id,
                "notes": f"POS Sale",
                "created_by": created_by,
                "created_at": now,
            }
            await self.movements.insert_one(movement)

            # Decrement item stock
            await self.items.update_one(
                {"_id": ObjectId(item["item_id"])},
                {"$inc": {"stock.current_stock": -item["quantity"]}},
            )

    async def _restore_stock(self, sale_id: str, items: list, created_by: str | None) -> None:
        """
        Create return_in movements to add stock back on sale return.
        """
        now = datetime.now(timezone.utc)
        for item in items:
            movement = {
                "item_id": item["item_id"],
                "item_name": item.get("item_name"),
                "movement_type": "stock_in",
                "quantity": item["quantity"],
                "unit_cost": item.get("unit_price"),
                "reference_type": "sale_return",
                "reference_id": sale_id,
                "notes": f"Sale return",
                "created_by": created_by,
                "created_at": now,
            }
            await self.movements.insert_one(movement)

            # Increment item stock back
            await self.items.update_one(
                {"_id": ObjectId(item["item_id"])},
                {"$inc": {"stock.current_stock": item["quantity"]}},
            )

    # ── Create Sale ──────────────────────────────────────────────

    async def create_sale(self, data: dict, created_by: str | None = None) -> dict:
        """
        Create a new sale / bill.

        If status is 'completed', stock is immediately deducted and invoice
        number is generated. If 'draft' or 'on_hold', stock is NOT touched
        until the sale is explicitly completed.
        """
        now = datetime.now(timezone.utc)
        sale_status = data.get("status", "completed")

        invoice_number = None
        if sale_status == "completed":
            invoice_number = await self._generate_invoice_number()

        sale_doc = {
            **data,
            "invoice_number": invoice_number,
            "is_deleted": False,
            "created_by": created_by,
            "created_at": now,
            "updated_at": now,
            "completed_at": now if sale_status == "completed" else None,
        }

        result = await self.sales.insert_one(sale_doc)
        sale_doc["_id"] = result.inserted_id
        sale_id = str(result.inserted_id)

        # Deduct stock only on completed sales
        if sale_status == "completed":
            await self._deduct_stock(sale_id, data.get("items", []), created_by)

        return serialize_mongo_doc(sale_doc)

    # ── Get Sale ─────────────────────────────────────────────────

    async def get_sale(self, sale_id: str) -> dict:
        """Get a single sale by ID with all line items and payment details."""
        if not ObjectId.is_valid(sale_id):
            raise HTTPException(status_code=400, detail="Invalid sale ID")
        doc = await self.sales.find_one(
            {"_id": ObjectId(sale_id), "is_deleted": {"$ne": True}}
        )
        if not doc:
            raise HTTPException(status_code=404, detail="Sale not found")
        return serialize_mongo_doc(doc)

    # ── List Sales ───────────────────────────────────────────────

    async def list_sales(
        self,
        status_filter: Optional[str] = None,
        customer_id: Optional[str] = None,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
        query: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        """
        List sales with optional filters.
        Search works on invoice_number, customer_name, customer_phone.
        """
        filters: dict = {"is_deleted": {"$ne": True}}

        if status_filter:
            filters["status"] = status_filter
        if customer_id:
            filters["customer_id"] = customer_id
        if query:
            filters["$or"] = [
                {"invoice_number": {"$regex": query, "$options": "i"}},
                {"customer_name": {"$regex": query, "$options": "i"}},
                {"customer_phone": {"$regex": query, "$options": "i"}},
            ]
        if from_date or to_date:
            date_filter = {}
            if from_date:
                date_filter["$gte"] = from_date
            if to_date:
                date_filter["$lte"] = to_date
            filters["created_at"] = date_filter

        total = await self.sales.count_documents(filters)
        cursor = self.sales.find(filters).skip(offset).limit(limit).sort("created_at", -1)
        docs = [serialize_mongo_doc(d) async for d in cursor]
        return docs, total

    # ── Hold Sale ────────────────────────────────────────────────

    async def hold_sale(self, sale_id: str, reason: str | None = None) -> dict:
        """
        Park a draft or in-progress sale for later.
        Customer will come back to complete it. Stock is NOT deducted.
        """
        if not ObjectId.is_valid(sale_id):
            raise HTTPException(status_code=400, detail="Invalid sale ID")

        result = await self.sales.find_one_and_update(
            {
                "_id": ObjectId(sale_id),
                "status": {"$in": ["draft", "on_hold"]},
                "is_deleted": {"$ne": True},
            },
            {
                "$set": {
                    "status": "on_hold",
                    "hold_reason": reason,
                    "updated_at": datetime.now(timezone.utc),
                }
            },
            return_document=True,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Sale not found or cannot be held")
        return serialize_mongo_doc(result)

    # ── Complete Sale ────────────────────────────────────────────

    async def complete_sale(
        self, sale_id: str, payment_data: dict, completed_by: str | None = None
    ) -> dict:
        """
        Complete a held/draft sale — record payment, deduct stock, generate invoice.
        """
        if not ObjectId.is_valid(sale_id):
            raise HTTPException(status_code=400, detail="Invalid sale ID")

        sale = await self.sales.find_one(
            {
                "_id": ObjectId(sale_id),
                "status": {"$in": ["draft", "on_hold"]},
                "is_deleted": {"$ne": True},
            }
        )
        if not sale:
            raise HTTPException(
                status_code=404,
                detail="Sale not found or already completed",
            )

        invoice_number = await self._generate_invoice_number()
        now = datetime.now(timezone.utc)

        result = await self.sales.find_one_and_update(
            {"_id": ObjectId(sale_id)},
            {
                "$set": {
                    "status": "completed",
                    "payments": payment_data.get("payments", []),
                    "amount_received": payment_data.get("amount_received"),
                    "change_due": payment_data.get("change_due"),
                    "invoice_number": invoice_number,
                    "completed_at": now,
                    "updated_at": now,
                }
            },
            return_document=True,
        )

        # Now deduct stock
        await self._deduct_stock(sale_id, sale.get("items", []), completed_by)

        return serialize_mongo_doc(result)

    # ── Cancel Sale ──────────────────────────────────────────────

    async def cancel_sale(self, sale_id: str) -> dict:
        """
        Cancel a draft or on_hold sale. Completed sales cannot be cancelled
        (use return instead).
        """
        if not ObjectId.is_valid(sale_id):
            raise HTTPException(status_code=400, detail="Invalid sale ID")

        result = await self.sales.find_one_and_update(
            {
                "_id": ObjectId(sale_id),
                "status": {"$in": ["draft", "on_hold"]},
                "is_deleted": {"$ne": True},
            },
            {
                "$set": {
                    "status": "cancelled",
                    "cancelled_at": datetime.now(timezone.utc),
                    "updated_at": datetime.now(timezone.utc),
                }
            },
            return_document=True,
        )
        if not result:
            raise HTTPException(
                status_code=404,
                detail="Sale not found or cannot be cancelled (already completed?)",
            )
        return serialize_mongo_doc(result)

    # ── Sale Return ──────────────────────────────────────────────

    async def process_return(
        self, sale_id: str, return_data: dict, created_by: str | None = None
    ) -> dict:
        """
        Process a return against a completed sale.

        1. Validates the sale exists and is completed
        2. Creates a return/credit note document
        3. Adds stock back via return_in movements
        4. Updates sale status to 'returned'
        """
        if not ObjectId.is_valid(sale_id):
            raise HTTPException(status_code=400, detail="Invalid sale ID")

        sale = await self.sales.find_one(
            {
                "_id": ObjectId(sale_id),
                "status": "completed",
                "is_deleted": {"$ne": True},
            }
        )
        if not sale:
            raise HTTPException(
                status_code=404,
                detail="Sale not found or not in completed status",
            )

        now = datetime.now(timezone.utc)

        # Create return document
        return_doc = {
            "sale_id": sale_id,
            "invoice_number": sale.get("invoice_number"),
            **return_data,
            "created_by": created_by,
            "created_at": now,
        }
        result = await self.returns.insert_one(return_doc)
        return_doc["_id"] = result.inserted_id

        # Restore stock
        await self._restore_stock(sale_id, return_data.get("items", []), created_by)

        # Update sale status
        await self.sales.update_one(
            {"_id": ObjectId(sale_id)},
            {"$set": {"status": "returned", "updated_at": now}},
        )

        return serialize_mongo_doc(return_doc)

    # ── Today's Summary ──────────────────────────────────────────

    async def get_daily_summary(self, date: Optional[datetime] = None) -> dict:
        """
        Get sales summary for a given day (defaults to today).
        Returns total sales, total amount, payment mode breakdown, and item count.
        """
        if not date:
            date = datetime.now(timezone.utc)

        start = date.replace(hour=0, minute=0, second=0, microsecond=0)
        end = date.replace(hour=23, minute=59, second=59, microsecond=999999)

        pipeline = [
            {
                "$match": {
                    "status": "completed",
                    "created_at": {"$gte": start, "$lte": end},
                    "is_deleted": {"$ne": True},
                }
            },
            {
                "$group": {
                    "_id": None,
                    "total_sales": {"$sum": 1},
                    "total_amount": {"$sum": "$grand_total"},
                    "total_tax": {"$sum": "$total_tax"},
                    "total_discount": {"$sum": {"$ifNull": ["$total_discount", 0]}},
                    "total_items_sold": {
                        "$sum": {"$size": {"$ifNull": ["$items", []]}}
                    },
                }
            },
        ]

        result = await self.sales.aggregate(pipeline).to_list(1)

        if result:
            summary = result[0]
            summary.pop("_id", None)
        else:
            summary = {
                "total_sales": 0,
                "total_amount": 0,
                "total_tax": 0,
                "total_discount": 0,
                "total_items_sold": 0,
            }

        summary["date"] = start.isoformat()
        return summary
