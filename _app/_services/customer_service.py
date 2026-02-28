from typing import List, Optional
from datetime import datetime
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

from app._schemas.customer_schema import (
    CustomerCreate,
    CustomerUpdate,
    CustomerResponse,
    CustomerList,
)
from app.utils.exceptions import NotFoundError, DuplicateError, ValidationError
from app.utils.helpers import serialize_datetime, calculate_pagination


class CustomerService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.customers_collection = db.customers
        self.sales_collection = db.sales

    async def create_customer(
        self, customer_data: CustomerCreate, current_user
    ) -> CustomerResponse:
        """Create a new customer"""
        # Check if email already exists (if provided)
        if customer_data.email:
            existing_customer = await self.customers_collection.find_one(
                {"email": customer_data.email}
            )
            if existing_customer:
                raise DuplicateError("Customer with this email already exists")

        # Convert customer data to dict and handle special types
        customer_dict = customer_data.dict()

        # Convert enum to string value
        if "customer_type" in customer_dict:
            customer_dict["customer_type"] = (
                customer_dict["customer_type"].value
                if hasattr(customer_dict["customer_type"], "value")
                else str(customer_dict["customer_type"])
            )

        customer_doc = {
            **customer_dict,
            "organization_id": ObjectId(current_user.organization_id),
            "outstanding_balance": 0.0,
            "loyalty_points": 0,
            "registration_date": datetime.utcnow(),
            "last_purchase": None,
        }

        result = await self.customers_collection.insert_one(customer_doc)
        created_customer = await self.customers_collection.find_one(
            {"_id": result.inserted_id}
        )

        return await self._serialize_customer_with_stats(created_customer)

    async def get_customer(self, customer_id: str) -> CustomerResponse:
        """Get customer by ID"""
        try:
            customer_doc = await self.customers_collection.find_one(
                {"_id": ObjectId(customer_id)}
            )
            if not customer_doc:
                raise NotFoundError("Customer not found")
            return await self._serialize_customer_with_stats(customer_doc)
        except Exception as e:
            if isinstance(e, NotFoundError):
                raise e
            raise ValidationError("Invalid customer ID")

    async def update_customer(
        self, customer_id: str, customer_data: CustomerUpdate
    ) -> CustomerResponse:
        """Update customer"""
        try:
            update_data = {
                k: v for k, v in customer_data.dict().items() if v is not None
            }
            if not update_data:
                raise ValidationError("No data provided for update")

            result = await self.customers_collection.update_one(
                {"_id": ObjectId(customer_id)}, {"$set": update_data}
            )

            if result.matched_count == 0:
                raise NotFoundError("Customer not found")

            updated_customer = await self.customers_collection.find_one(
                {"_id": ObjectId(customer_id)}
            )
            return await self._serialize_customer_with_stats(updated_customer)
        except Exception as e:
            if isinstance(e, (NotFoundError, ValidationError)):
                raise e
            raise ValidationError("Invalid customer ID")

    async def delete_customer(self, customer_id: str) -> bool:
        """Delete customer"""
        try:
            result = await self.customers_collection.delete_one(
                {"_id": ObjectId(customer_id)}
            )
            return result.deleted_count > 0
        except:
            return False

    async def list_customers(
        self,
        page: int = 1,
        per_page: int = 20,
        customer_type: Optional[str] = None,
        search: Optional[str] = None,
    ) -> CustomerList:
        """List customers with pagination and filters"""
        skip = (page - 1) * per_page
        query = {}

        if customer_type:
            query["customer_type"] = customer_type

        if search:
            query["$or"] = [
                {"name": {"$regex": search, "$options": "i"}},
                {"email": {"$regex": search, "$options": "i"}},
                {"phone": {"$regex": search, "$options": "i"}},
            ]

        total = await self.customers_collection.count_documents(query)
        customers_cursor = (
            self.customers_collection.find(query)
            .sort("registration_date", -1)
            .skip(skip)
            .limit(per_page)
        )
        customers = await customers_cursor.to_list(length=per_page)

        serialized_customers = []
        for customer in customers:
            serialized_customers.append(
                await self._serialize_customer_with_stats(customer)
            )

        return CustomerList(
            customers=serialized_customers,
            **calculate_pagination(page, per_page, total),
        )

    async def get_customer_purchase_history(
        self, customer_id: str, page: int = 1, per_page: int = 10
    ):
        """Get customer's purchase history"""
        skip = (page - 1) * per_page

        query = {"customer_id": ObjectId(customer_id)}
        total = await self.sales_collection.count_documents(query)

        sales_cursor = (
            self.sales_collection.find(query)
            .sort("sale_date", -1)
            .skip(skip)
            .limit(per_page)
        )
        sales = await sales_cursor.to_list(length=per_page)

        return {"purchases": sales, **calculate_pagination(page, per_page, total)}

    async def _serialize_customer_with_stats(
        self, customer_doc: dict
    ) -> CustomerResponse:
        """Convert customer document to CustomerResponse with calculated stats"""
        # Calculate total purchases and purchase count
        stats_pipeline = [
            {"$match": {"customer_id": customer_doc["_id"]}},
            {
                "$group": {
                    "_id": None,
                    "total_purchases": {"$sum": "$total_amount"},
                    "purchase_count": {"$sum": 1},
                }
            },
        ]

        stats_result = await self.sales_collection.aggregate(stats_pipeline).to_list(
            length=1
        )
        stats = (
            stats_result[0]
            if stats_result
            else {"total_purchases": 0, "purchase_count": 0}
        )

        return CustomerResponse(
            id=str(customer_doc["_id"]),
            name=customer_doc["name"],
            email=customer_doc.get("email"),
            phone=customer_doc.get("phone"),
            address=customer_doc.get("address"),
            customer_type=customer_doc["customer_type"],
            outstanding_balance=customer_doc["outstanding_balance"],
            loyalty_points=customer_doc["loyalty_points"],
            registration_date=serialize_datetime(customer_doc["registration_date"]),
            last_purchase=serialize_datetime(customer_doc.get("last_purchase")),
            total_purchases=stats["total_purchases"],
            purchase_count=stats["purchase_count"],
        )
