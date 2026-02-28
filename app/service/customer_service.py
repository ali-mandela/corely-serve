from motor.motor_asyncio import AsyncIOMotorDatabase
from datetime import datetime, timezone
from fastapi import HTTPException, status
from typing import Optional, Tuple
from app.utils.helpers import success_response, error_response, serialize_mongo_doc
from bson import ObjectId


class CustomerService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db

    async def create_customer(self, customer_data: dict, c: dict):
        customer_dict = customer_data.dict(exclude_unset=True)

        if customer_dict.get("other_meta") is None:
            customer_dict["other_meta"] = {}

        # Check for existing customer by email or phone
        query = {
            "$or": [
                {"email": customer_dict.get("email")},
                {"phone": customer_dict.get("phone")},
            ]
        }
        existing = await self.db["customers"].find_one(query)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Customer with this email or phone already exists",
            )

        # Metadata
        customer_dict.update(
            {
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "created_by": c.get("sub"),
                "organization_id": c.get("organization_id"),
            }
        )

        # Insert into DB
        result = await self.db["customers"].insert_one(customer_dict)
        if result.inserted_id:
            customer_dict["_id"] = str(result.inserted_id)
            return serialize_mongo_doc(customer_dict)
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create customer",
            )

    async def get_customer_by_id(self, customer_id: ObjectId):
        customer = await self.db["customers"].find_one({"_id": customer_id})
        if customer:
            return serialize_mongo_doc(customer)

    async def delete_customer(self, customer_id: str):
        if not ObjectId.is_valid(customer_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid customer ID"
            )

        # Check if customer exists and not already deleted
        customer = await self.db["customers"].find_one({"_id": ObjectId(customer_id)})
        if not customer:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found"
            )
        if customer.get("is_deleted", False):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Customer already deleted",
            )

        # Soft delete by setting is_deleted to True
        result = await self.db["customers"].update_one(
            {"_id": ObjectId(customer_id)},
            {"$set": {"is_deleted": True, "deleted_at": datetime.utcnow()}},
        )

        if result.modified_count == 1:
            return success_response(message="Customer deleted successfully")
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete customer",
            )

    async def list_customers(
        self, query: Optional[str] = None, limit: int = 10, offset: int = 0
    ) -> Tuple[list, int]:
        """
        List customers with optional search and pagination.

        Returns:
            Tuple of (list of customers, total count)
        """
        filters = {}
        if query:
            # Search by first_name, last_name, email, or phone (case-insensitive)
            filters["$or"] = [
                {"first_name": {"$regex": query, "$options": "i"}},
                {"last_name": {"$regex": query, "$options": "i"}},
                {"email": {"$regex": query, "$options": "i"}},
                {"phone": {"$regex": query, "$options": "i"}},
            ]

        filters["$or"] = [
            {"is_deleted": False},
            {"is_deleted": {"$exists": False}},
        ]

        total = await self.db["customers"].count_documents(filters)

        cursor = (
            self.db["customers"]
            .find(filters)
            .skip(offset)
            .limit(limit)
            .sort("created_at", -1)  # Optional: latest first
        )

        customers = []
        async for customer in cursor:
            customers.append(serialize_mongo_doc(customer))

        return customers, total

    async def update_customer(self, customer_id: str, update_data: dict):
        if not ObjectId.is_valid(customer_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid customer ID"
            )

        update_data = {k: v for k, v in update_data.items() if v is not None}
        if not update_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No data provided for update",
            )

        update_data["updated_at"] = datetime.utcnow()

        result = await self.db["customers"].find_one_and_update(
            {"_id": ObjectId(customer_id), "is_deleted": {"$ne": True}},
            {"$set": update_data},
            return_document=True,
        )

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Customer not found or already deleted",
            )

        return serialize_mongo_doc(result)
