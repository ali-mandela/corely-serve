"""Customer service — CRUD on tenant-scoped customers collection."""

from datetime import datetime, timezone
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase
from fastapi import HTTPException, status
from bson import ObjectId

from base.tenant import get_tenant_collection
from base.utils import serialize_mongo_doc


class CustomerService:
    def __init__(self, db: AsyncIOMotorDatabase, org_slug: str):
        self.db = db
        self.org_slug = org_slug
        self.customers = get_tenant_collection(db, org_slug, "customers")

    async def create_customer(self, data: dict, created_by: str | None = None) -> dict:
        """Create a new customer. Checks for duplicate phone number."""
        # Duplicate phone check
        existing = await self.customers.find_one(
            {"phone": data["phone"], "is_deleted": {"$ne": True}}
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Customer with phone '{data['phone']}' already exists",
            )

        now = datetime.now(timezone.utc)
        doc = {
            **data,
            "is_deleted": False,
            "created_by": created_by,
            "created_at": now,
            "updated_at": now,
        }
        result = await self.customers.insert_one(doc)
        doc["_id"] = result.inserted_id
        return serialize_mongo_doc(doc)

    async def get_customer(self, customer_id: str) -> dict:
        """Get a single customer by ID."""
        if not ObjectId.is_valid(customer_id):
            raise HTTPException(status_code=400, detail="Invalid customer ID")
        doc = await self.customers.find_one(
            {"_id": ObjectId(customer_id), "is_deleted": {"$ne": True}}
        )
        if not doc:
            raise HTTPException(status_code=404, detail="Customer not found")
        return serialize_mongo_doc(doc)

    async def list_customers(
        self,
        query: Optional[str] = None,
        customer_type: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        """List customers with search (name, phone, email, company, GSTIN) and type filter."""
        filters: dict = {"is_deleted": {"$ne": True}}
        if query:
            filters["$or"] = [
                {"name": {"$regex": query, "$options": "i"}},
                {"phone": {"$regex": query, "$options": "i"}},
                {"email": {"$regex": query, "$options": "i"}},
                {"company_name": {"$regex": query, "$options": "i"}},
                {"gstin": {"$regex": query, "$options": "i"}},
            ]
        if customer_type:
            filters["customer_type"] = customer_type

        total = await self.customers.count_documents(filters)
        cursor = self.customers.find(filters).skip(offset).limit(limit).sort("created_at", -1)
        docs = [serialize_mongo_doc(d) async for d in cursor]
        return docs, total

    async def update_customer(self, customer_id: str, update_data: dict) -> dict:
        """Update customer fields. Only non-None fields are updated."""
        if not ObjectId.is_valid(customer_id):
            raise HTTPException(status_code=400, detail="Invalid customer ID")
        update_data["updated_at"] = datetime.now(timezone.utc)
        clean = {k: v for k, v in update_data.items() if v is not None}
        result = await self.customers.find_one_and_update(
            {"_id": ObjectId(customer_id), "is_deleted": {"$ne": True}},
            {"$set": clean},
            return_document=True,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Customer not found")
        return serialize_mongo_doc(result)

    async def delete_customer(self, customer_id: str) -> dict:
        """Soft-delete a customer (sets is_deleted=True)."""
        if not ObjectId.is_valid(customer_id):
            raise HTTPException(status_code=400, detail="Invalid customer ID")
        result = await self.customers.update_one(
            {"_id": ObjectId(customer_id), "is_deleted": {"$ne": True}},
            {"$set": {"is_deleted": True, "deleted_at": datetime.now(timezone.utc)}},
        )
        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Customer not found or already deleted")
        return {"message": "Customer deleted successfully"}
