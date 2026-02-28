from motor.motor_asyncio import AsyncIOMotorDatabase
from app.utils.helpers import success_response, error_response, serialize_mongo_doc
from datetime import datetime, timezone
from uuid import uuid4
from bson import ObjectId
from typing import Optional, Dict, Any


class ProductService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self._db = db

    async def create_product(self, product_data: dict, c: dict):
        # If using Pydantic model, convert to dict
        product_dict = (
            product_data.dict(exclude_unset=True)
            if hasattr(product_data, "dict")
            else dict(product_data)
        )

        # Ensure other_meta exists
        if product_dict.get("other_meta") is None:
            product_dict["other_meta"] = {}

        # Add meta fields
        product_dict.update(
            {
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "created_by": c.get("sub"),
                "organization_id": c.get("organization_id"),
            }
        )

        # Insert into MongoDB
        result = await self._db["products"].insert_one(product_dict)

        # Return inserted document or ID
        if result.inserted_id:
            # Return inserted_id as string
            product_dict["_id"] = str(result.inserted_id)
            return serialize_mongo_doc(product_dict)
        return None

    async def get_product_by_id(self, product_id: ObjectId):
        product = await self._db["products"].find_one({"_id": product_id})
        if product:
            return serialize_mongo_doc(product)
        return None

    async def list_products(
        self,
        category: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 20,
        skip: int = 0,
    ):
        """
        Fetch products with optional filtering, search, and pagination.
        """
        query = {}
        if category:
            query["category"] = category
        if search:
            query["$or"] = [
                {"name": {"$regex": search, "$options": "i"}},
                {"description": {"$regex": search, "$options": "i"}},
            ]

        cursor = self._db["products"].find(query).skip(skip).limit(limit)
        products = []
        async for doc in cursor:
            products.append(serialize_mongo_doc(doc))

        total_count = await self._db["products"].count_documents(query)

        return {
            "products": products,
            "pagination": {"total": total_count, "limit": limit, "skip": skip},
        }

    async def delete_product(self, product_id: str) -> bool:
        """
        Delete a product by its ID.
        Returns True if a product was deleted, False otherwise.
        """
        if not ObjectId.is_valid(product_id):
            return False

        result = await self._db["products"].delete_one({"_id": ObjectId(product_id)})
        return result.deleted_count > 0

    async def update_product(
        self, product_id: str, update_data: Dict[str, Any]
    ) -> dict | None:
        """
        Patch (update) a product partially.
        Returns the updated product if successful, None if not found.
        """
        if not ObjectId.is_valid(product_id):
            return None

        # Prevent _id modification
        update_data.pop("_id", None)
        update_data["updated_at"] = datetime.utcnow()

        result = await self._db["products"].find_one_and_update(
            {"_id": ObjectId(product_id)},
            {"$set": update_data},
            return_document=True,  # Return the updated document
        )

        if result:
            return serialize_mongo_doc(result)
        return None
