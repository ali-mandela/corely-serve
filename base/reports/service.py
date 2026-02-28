"""
Reports Service — business intelligence aggregation pipelines.

Provides the owner/admin with analytics across:
    - Sales: daily/weekly/monthly summaries, top items, category breakdown
    - Inventory: stock value, low stock alerts, movement summary
    - Financial: revenue, tax collected, outstanding payments
    - Customers: top buyers, credit outstanding
    - Vendors: payment dues, purchase volume

All queries use MongoDB aggregation pipelines for performance.
Collection prefixes: {slug}_sales, {slug}_items, {slug}_invoices, etc.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

from base.tenant import get_tenant_collection
from base.utils import serialize_mongo_doc


class ReportsService:
    def __init__(self, db: AsyncIOMotorDatabase, org_slug: str):
        self.db = db
        self.org_slug = org_slug
        self.sales = get_tenant_collection(db, org_slug, "sales")
        self.items = get_tenant_collection(db, org_slug, "items")
        self.invoices = get_tenant_collection(db, org_slug, "invoices")
        self.customers = get_tenant_collection(db, org_slug, "customers")
        self.vendors = get_tenant_collection(db, org_slug, "vendors")
        self.purchases = get_tenant_collection(db, org_slug, "purchase_entries")
        self.movements = get_tenant_collection(db, org_slug, "stock_movements")

    # ── Dashboard Overview ───────────────────────────────────────

    async def get_dashboard(self) -> dict:
        """
        Owner's dashboard — single API call returns everything at a glance.
        Today's sales, this month's revenue, low stock count, pending payments.
        """
        now = datetime.now(timezone.utc)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        # Today's sales
        today_pipeline = [
            {"$match": {"status": "completed", "created_at": {"$gte": today_start}, "is_deleted": {"$ne": True}}},
            {"$group": {
                "_id": None,
                "count": {"$sum": 1},
                "revenue": {"$sum": "$grand_total"},
                "tax": {"$sum": "$total_tax"},
            }},
        ]
        today_result = await self.sales.aggregate(today_pipeline).to_list(1)
        today = today_result[0] if today_result else {"count": 0, "revenue": 0, "tax": 0}
        today.pop("_id", None)

        # This month's sales
        month_pipeline = [
            {"$match": {"status": "completed", "created_at": {"$gte": month_start}, "is_deleted": {"$ne": True}}},
            {"$group": {
                "_id": None,
                "count": {"$sum": 1},
                "revenue": {"$sum": "$grand_total"},
                "tax": {"$sum": "$total_tax"},
            }},
        ]
        month_result = await self.sales.aggregate(month_pipeline).to_list(1)
        month = month_result[0] if month_result else {"count": 0, "revenue": 0, "tax": 0}
        month.pop("_id", None)

        # Low stock items
        low_stock_count = await self.items.count_documents({
            "is_deleted": {"$ne": True},
            "$expr": {"$lte": ["$stock.current_stock", "$stock.min_stock_level"]},
        })

        # Total inventory items
        total_items = await self.items.count_documents({"is_deleted": {"$ne": True}})

        # Total customers & vendors
        total_customers = await self.customers.count_documents({"is_deleted": {"$ne": True}})
        total_vendors = await self.vendors.count_documents({"is_deleted": {"$ne": True}})

        # Pending purchase payments
        pending_pipeline = [
            {"$match": {"payment_status": {"$in": ["unpaid", "partial"]}}},
            {"$group": {
                "_id": None,
                "count": {"$sum": 1},
                "total_due": {"$sum": {"$subtract": ["$grand_total", {"$ifNull": ["$amount_paid", 0]}]}},
            }},
        ]
        pending_result = await self.purchases.aggregate(pending_pipeline).to_list(1)
        pending = pending_result[0] if pending_result else {"count": 0, "total_due": 0}
        pending.pop("_id", None)

        return {
            "today": today,
            "this_month": month,
            "low_stock_items": low_stock_count,
            "total_items": total_items,
            "total_customers": total_customers,
            "total_vendors": total_vendors,
            "pending_payments": pending,
            "generated_at": now.isoformat(),
        }

    # ── Sales Reports ────────────────────────────────────────────

    async def sales_summary(
        self, period: str = "daily", from_date: datetime | None = None, to_date: datetime | None = None
    ) -> list[dict]:
        """
        Sales summary grouped by period (daily/weekly/monthly).
        Returns date, total_sales, total_revenue, total_tax, total_discount.
        """
        now = datetime.now(timezone.utc)
        if not from_date:
            from_date = now - timedelta(days=30)
        if not to_date:
            to_date = now

        date_format = {
            "daily": "%Y-%m-%d",
            "weekly": "%Y-W%V",
            "monthly": "%Y-%m",
        }.get(period, "%Y-%m-%d")

        pipeline = [
            {"$match": {
                "status": "completed",
                "is_deleted": {"$ne": True},
                "created_at": {"$gte": from_date, "$lte": to_date},
            }},
            {"$group": {
                "_id": {"$dateToString": {"format": date_format, "date": "$created_at"}},
                "total_sales": {"$sum": 1},
                "total_revenue": {"$sum": "$grand_total"},
                "total_tax": {"$sum": "$total_tax"},
                "total_discount": {"$sum": {"$ifNull": ["$total_discount", 0]}},
                "total_items_sold": {"$sum": {"$size": {"$ifNull": ["$items", []]}}},
            }},
            {"$sort": {"_id": 1}},
        ]

        results = await self.sales.aggregate(pipeline).to_list(100)
        return [{"period": r.pop("_id"), **r} for r in results]

    async def top_selling_items(self, limit: int = 10, days: int = 30) -> list[dict]:
        """
        Top selling items by quantity in the last N days.
        Returns item_name, total_quantity, total_revenue.
        """
        from_date = datetime.now(timezone.utc) - timedelta(days=days)

        pipeline = [
            {"$match": {
                "status": "completed",
                "is_deleted": {"$ne": True},
                "created_at": {"$gte": from_date},
            }},
            {"$unwind": "$items"},
            {"$group": {
                "_id": "$items.item_id",
                "item_name": {"$first": "$items.item_name"},
                "sku": {"$first": "$items.sku"},
                "total_quantity": {"$sum": "$items.quantity"},
                "total_revenue": {"$sum": "$items.line_total"},
                "times_sold": {"$sum": 1},
            }},
            {"$sort": {"total_quantity": -1}},
            {"$limit": limit},
        ]

        return await self.sales.aggregate(pipeline).to_list(limit)

    async def sales_by_category(self, days: int = 30) -> list[dict]:
        """
        Sales breakdown by item category in the last N days.
        Requires items to have a category field. Falls back to 'Uncategorized'.
        """
        from_date = datetime.now(timezone.utc) - timedelta(days=days)

        pipeline = [
            {"$match": {
                "status": "completed",
                "is_deleted": {"$ne": True},
                "created_at": {"$gte": from_date},
            }},
            {"$unwind": "$items"},
            {"$lookup": {
                "from": f"{self.org_slug}_items",
                "let": {"item_id": {"$toObjectId": "$items.item_id"}},
                "pipeline": [
                    {"$match": {"$expr": {"$eq": ["$_id", "$$item_id"]}}},
                    {"$project": {"category": 1}},
                ],
                "as": "item_detail",
            }},
            {"$unwind": {"path": "$item_detail", "preserveNullAndEmptyArrays": True}},
            {"$group": {
                "_id": {"$ifNull": ["$item_detail.category", "uncategorized"]},
                "total_quantity": {"$sum": "$items.quantity"},
                "total_revenue": {"$sum": "$items.line_total"},
                "items_count": {"$addToSet": "$items.item_id"},
            }},
            {"$project": {
                "category": "$_id",
                "_id": 0,
                "total_quantity": 1,
                "total_revenue": 1,
                "unique_items": {"$size": "$items_count"},
            }},
            {"$sort": {"total_revenue": -1}},
        ]

        return await self.sales.aggregate(pipeline).to_list(50)

    async def payment_mode_breakdown(self, days: int = 30) -> list[dict]:
        """
        Revenue breakdown by payment mode (cash, UPI, card, credit, etc.)
        in the last N days.
        """
        from_date = datetime.now(timezone.utc) - timedelta(days=days)

        pipeline = [
            {"$match": {
                "status": "completed",
                "is_deleted": {"$ne": True},
                "created_at": {"$gte": from_date},
            }},
            {"$unwind": {"path": "$payments", "preserveNullAndEmptyArrays": True}},
            {"$group": {
                "_id": {"$ifNull": ["$payments.mode", "cash"]},
                "total_amount": {"$sum": {"$ifNull": ["$payments.amount", "$grand_total"]}},
                "transaction_count": {"$sum": 1},
            }},
            {"$project": {"mode": "$_id", "_id": 0, "total_amount": 1, "transaction_count": 1}},
            {"$sort": {"total_amount": -1}},
        ]

        return await self.sales.aggregate(pipeline).to_list(20)

    # ── Inventory Reports ────────────────────────────────────────

    async def stock_valuation(self) -> dict:
        """
        Total inventory valuation.
        Calculates: total items, total stock value (cost_price * current_stock),
        total retail value (selling_price * current_stock).
        """
        pipeline = [
            {"$match": {"is_deleted": {"$ne": True}}},
            {"$group": {
                "_id": None,
                "total_items": {"$sum": 1},
                "total_stock_units": {"$sum": "$stock.current_stock"},
                "cost_value": {"$sum": {
                    "$multiply": [
                        {"$ifNull": ["$stock.current_stock", 0]},
                        {"$ifNull": ["$pricing.cost_price", 0]},
                    ]
                }},
                "retail_value": {"$sum": {
                    "$multiply": [
                        {"$ifNull": ["$stock.current_stock", 0]},
                        {"$ifNull": ["$pricing.selling_price", 0]},
                    ]
                }},
            }},
        ]

        result = await self.items.aggregate(pipeline).to_list(1)
        if result:
            summary = result[0]
            summary.pop("_id", None)
            summary["potential_profit"] = round(
                summary.get("retail_value", 0) - summary.get("cost_value", 0), 2
            )
        else:
            summary = {
                "total_items": 0, "total_stock_units": 0,
                "cost_value": 0, "retail_value": 0, "potential_profit": 0,
            }
        return summary

    async def low_stock_report(self, limit: int = 50) -> list[dict]:
        """
        Items where current_stock <= min_stock_level.
        Sorted by urgency (most critically low first).
        """
        pipeline = [
            {"$match": {
                "is_deleted": {"$ne": True},
                "$expr": {"$lte": ["$stock.current_stock", "$stock.min_stock_level"]},
            }},
            {"$project": {
                "name": 1, "sku": 1, "category": 1, "unit": 1,
                "current_stock": "$stock.current_stock",
                "min_stock_level": "$stock.min_stock_level",
                "reorder_level": "$stock.reorder_level",
                "cost_price": "$pricing.cost_price",
                "deficit": {"$subtract": ["$stock.min_stock_level", "$stock.current_stock"]},
            }},
            {"$sort": {"deficit": -1}},
            {"$limit": limit},
        ]

        results = await self.items.aggregate(pipeline).to_list(limit)
        return [serialize_mongo_doc(r) for r in results]

    # ── Customer / Vendor Reports ────────────────────────────────

    async def top_customers(self, limit: int = 10, days: int = 90) -> list[dict]:
        """
        Top customers by purchase amount in the last N days.
        Only includes sales linked to a customer_id.
        """
        from_date = datetime.now(timezone.utc) - timedelta(days=days)

        pipeline = [
            {"$match": {
                "status": "completed",
                "is_deleted": {"$ne": True},
                "customer_id": {"$ne": None},
                "created_at": {"$gte": from_date},
            }},
            {"$group": {
                "_id": "$customer_id",
                "customer_name": {"$first": "$customer_name"},
                "total_purchases": {"$sum": 1},
                "total_amount": {"$sum": "$grand_total"},
                "last_purchase": {"$max": "$created_at"},
            }},
            {"$sort": {"total_amount": -1}},
            {"$limit": limit},
        ]

        return await self.sales.aggregate(pipeline).to_list(limit)

    async def vendor_dues(self) -> list[dict]:
        """
        Outstanding payment dues to vendors.
        Shows vendors with unpaid/partially paid purchase entries.
        """
        pipeline = [
            {"$match": {"payment_status": {"$in": ["unpaid", "partial"]}}},
            {"$group": {
                "_id": "$supplier.name",
                "gstin": {"$first": "$supplier.gstin"},
                "total_purchases": {"$sum": 1},
                "total_amount": {"$sum": "$grand_total"},
                "total_paid": {"$sum": {"$ifNull": ["$amount_paid", 0]}},
            }},
            {"$addFields": {
                "outstanding": {"$subtract": ["$total_amount", "$total_paid"]},
            }},
            {"$sort": {"outstanding": -1}},
        ]

        results = await self.purchases.aggregate(pipeline).to_list(50)
        return [{"vendor_name": r.pop("_id"), **r} for r in results]

    # ── GST Report ───────────────────────────────────────────────

    async def gst_summary(
        self, from_date: datetime | None = None, to_date: datetime | None = None
    ) -> dict:
        """
        GST tax summary for a period — useful for filing GST returns.
        Returns total CGST, SGST, IGST collected from sales.
        """
        now = datetime.now(timezone.utc)
        if not from_date:
            from_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        if not to_date:
            to_date = now

        pipeline = [
            {"$match": {
                "invoice_type": "tax_invoice",
                "status": {"$in": ["issued", "paid"]},
                "is_deleted": {"$ne": True},
                "created_at": {"$gte": from_date, "$lte": to_date},
            }},
            {"$group": {
                "_id": None,
                "total_invoices": {"$sum": 1},
                "taxable_total": {"$sum": "$taxable_total"},
                "cgst_collected": {"$sum": {"$ifNull": ["$cgst_total", 0]}},
                "sgst_collected": {"$sum": {"$ifNull": ["$sgst_total", 0]}},
                "igst_collected": {"$sum": {"$ifNull": ["$igst_total", 0]}},
                "cess_collected": {"$sum": {"$ifNull": ["$cess_total", 0]}},
                "total_tax_collected": {"$sum": "$total_tax"},
                "total_revenue": {"$sum": "$grand_total"},
            }},
        ]

        result = await self.invoices.aggregate(pipeline).to_list(1)
        if result:
            summary = result[0]
            summary.pop("_id", None)
        else:
            summary = {
                "total_invoices": 0, "taxable_total": 0,
                "cgst_collected": 0, "sgst_collected": 0,
                "igst_collected": 0, "cess_collected": 0,
                "total_tax_collected": 0, "total_revenue": 0,
            }

        summary["period"] = {"from": from_date.isoformat(), "to": to_date.isoformat()}
        return summary
