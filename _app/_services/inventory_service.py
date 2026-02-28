from typing import List, Optional, Dict, Any
from datetime import datetime
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

from app._schemas.product_schema import ProductCreate, ProductUpdate, ProductResponse, ProductList
from app._schemas.inventory_schema import (
    InventoryCreate, InventoryUpdate, InventoryResponse, InventoryList,
    InventoryAdjustment, InventoryTransfer, StockAlert
)
from app.utils.exceptions import NotFoundError, DuplicateError, ValidationError
from app.utils.helpers import serialize_datetime, calculate_pagination, generate_invoice_number


class InventoryService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.products_collection = db.products
        self.inventory_collection = db.inventory
        self.stores_collection = db.stores

    async def create_product(self, product_data: ProductCreate, current_user) -> ProductResponse:
        """Create a new product"""
        # Check if SKU already exists within the organization
        existing_product = await self.products_collection.find_one({
            "sku": product_data.sku,
            "organization_id": ObjectId(current_user.organization_id)
        })
        if existing_product:
            raise DuplicateError("Product with this SKU already exists in your organization")

        # Convert product data to dict and handle special types
        product_dict = product_data.dict()

        # Convert Decimal types to float for MongoDB
        decimal_fields = ['cost_price', 'selling_price', 'discount_price', 'weight']
        for field in decimal_fields:
            if field in product_dict and product_dict[field] is not None:
                product_dict[field] = float(product_dict[field])

        # Create product document
        product_doc = {
            **product_dict,
            "organization_id": ObjectId(current_user.organization_id),
            "is_active": True,
            "created_at": datetime.utcnow()
        }

        result = await self.products_collection.insert_one(product_doc)
        created_product = await self.products_collection.find_one({"_id": result.inserted_id})
        
        return self._serialize_product(created_product)

    async def get_product(self, product_id: str) -> ProductResponse:
        """Get product by ID"""
        try:
            product_doc = await self.products_collection.find_one({"_id": ObjectId(product_id)})
            if not product_doc:
                raise NotFoundError("Product not found")
            return self._serialize_product(product_doc)
        except Exception as e:
            if isinstance(e, NotFoundError):
                raise e
            raise ValidationError("Invalid product ID")

    async def update_product(self, product_id: str, product_data: ProductUpdate) -> ProductResponse:
        """Update product"""
        try:
            update_data = {k: v for k, v in product_data.dict().items() if v is not None}
            if not update_data:
                raise ValidationError("No data provided for update")

            result = await self.products_collection.update_one(
                {"_id": ObjectId(product_id)},
                {"$set": update_data}
            )

            if result.matched_count == 0:
                raise NotFoundError("Product not found")

            updated_product = await self.products_collection.find_one({"_id": ObjectId(product_id)})
            return self._serialize_product(updated_product)
        except Exception as e:
            if isinstance(e, (NotFoundError, ValidationError)):
                raise e
            raise ValidationError("Invalid product ID")

    async def delete_product(self, product_id: str) -> bool:
        """Soft delete product"""
        try:
            result = await self.products_collection.update_one(
                {"_id": ObjectId(product_id)},
                {"$set": {"is_active": False}}
            )
            return result.matched_count > 0
        except:
            return False

    async def list_products(self, page: int = 1, per_page: int = 20, category: Optional[str] = None,
                          search: Optional[str] = None, store_id: Optional[str] = None) -> ProductList:
        """List products with pagination and filters"""
        skip = (page - 1) * per_page
        query = {"is_active": True}

        if category:
            query["category"] = {"$regex": category, "$options": "i"}
        
        if search:
            query["$or"] = [
                {"name": {"$regex": search, "$options": "i"}},
                {"sku": {"$regex": search, "$options": "i"}},
                {"description": {"$regex": search, "$options": "i"}}
            ]

        total = await self.products_collection.count_documents(query)
        products_cursor = self.products_collection.find(query).skip(skip).limit(per_page)
        products = await products_cursor.to_list(length=per_page)

        return ProductList(
            products=[self._serialize_product(product) for product in products],
            **calculate_pagination(page, per_page, total)
        )

    async def create_inventory(self, inventory_data: InventoryCreate, current_user) -> InventoryResponse:
        """Create inventory record for a product at a store"""
        # Check if inventory already exists for this product/store combination
        existing_inventory = await self.inventory_collection.find_one({
            "product_id": ObjectId(inventory_data.product_id),
            "store_id": ObjectId(inventory_data.store_id),
            "organization_id": ObjectId(current_user.organization_id)
        })

        if existing_inventory:
            raise DuplicateError("Inventory record already exists for this product at this store")

        inventory_doc = {
            "product_id": ObjectId(inventory_data.product_id),
            "store_id": ObjectId(inventory_data.store_id),
            "quantity": inventory_data.quantity,
            "reserved_quantity": 0,
            "reorder_point": inventory_data.reorder_point,
            "max_stock": inventory_data.max_stock,
            "organization_id": ObjectId(current_user.organization_id),
            "last_updated": datetime.utcnow()
        }

        result = await self.inventory_collection.insert_one(inventory_doc)
        created_inventory = await self.inventory_collection.find_one({"_id": result.inserted_id})
        
        return await self._serialize_inventory_with_details(created_inventory)

    async def update_inventory(self, inventory_id: str, inventory_data: InventoryUpdate) -> InventoryResponse:
        """Update inventory record"""
        try:
            update_data = {k: v for k, v in inventory_data.dict().items() if v is not None}
            update_data["last_updated"] = datetime.utcnow()

            result = await self.inventory_collection.update_one(
                {"_id": ObjectId(inventory_id)},
                {"$set": update_data}
            )

            if result.matched_count == 0:
                raise NotFoundError("Inventory record not found")

            updated_inventory = await self.inventory_collection.find_one({"_id": ObjectId(inventory_id)})
            return await self._serialize_inventory_with_details(updated_inventory)
        except Exception as e:
            if isinstance(e, NotFoundError):
                raise e
            raise ValidationError("Invalid inventory ID")

    async def adjust_inventory(self, adjustment: InventoryAdjustment, user_id: str) -> InventoryResponse:
        """Adjust inventory quantity"""
        inventory_doc = await self.inventory_collection.find_one({
            "product_id": ObjectId(adjustment.product_id),
            "store_id": ObjectId(adjustment.store_id)
        })

        if not inventory_doc:
            raise NotFoundError("Inventory record not found")

        new_quantity = inventory_doc["quantity"] + adjustment.adjustment_quantity
        if new_quantity < 0:
            raise ValidationError("Adjustment would result in negative inventory")

        # Update inventory
        await self.inventory_collection.update_one(
            {"_id": inventory_doc["_id"]},
            {
                "$set": {
                    "quantity": new_quantity,
                    "last_updated": datetime.utcnow()
                }
            }
        )

        # Log the adjustment (you might want to create an adjustments collection)
        adjustment_log = {
            "inventory_id": inventory_doc["_id"],
            "product_id": ObjectId(adjustment.product_id),
            "store_id": ObjectId(adjustment.store_id),
            "adjustment_quantity": adjustment.adjustment_quantity,
            "previous_quantity": inventory_doc["quantity"],
            "new_quantity": new_quantity,
            "reason": adjustment.reason,
            "notes": adjustment.notes,
            "user_id": ObjectId(user_id),
            "created_at": datetime.utcnow()
        }
        
        await self.db.inventory_adjustments.insert_one(adjustment_log)

        updated_inventory = await self.inventory_collection.find_one({"_id": inventory_doc["_id"]})
        return await self._serialize_inventory_with_details(updated_inventory)

    async def get_store_inventory(self, store_id: str, current_user, page: int = 1, per_page: int = 20) -> InventoryList:
        """Get inventory for a specific store"""
        skip = (page - 1) * per_page
        query = {
            "store_id": ObjectId(store_id),
            "organization_id": ObjectId(current_user.organization_id)
        }

        total = await self.inventory_collection.count_documents(query)
        inventory_cursor = self.inventory_collection.find(query).skip(skip).limit(per_page)
        inventory_items = await inventory_cursor.to_list(length=per_page)

        # Calculate counts
        low_stock_count = await self.inventory_collection.count_documents({
            "store_id": ObjectId(store_id),
            "organization_id": ObjectId(current_user.organization_id),
            "$expr": {"$lte": ["$quantity", "$reorder_point"]}
        })

        out_of_stock_count = await self.inventory_collection.count_documents({
            "store_id": ObjectId(store_id),
            "organization_id": ObjectId(current_user.organization_id),
            "quantity": 0
        })

        serialized_inventory = []
        for item in inventory_items:
            serialized_inventory.append(await self._serialize_inventory_with_details(item))

        return InventoryList(
            inventory=serialized_inventory,
            total=total,
            low_stock_count=low_stock_count,
            out_of_stock_count=out_of_stock_count
        )

    async def get_low_stock_alerts(self, store_id: Optional[str] = None) -> List[StockAlert]:
        """Get low stock alerts"""
        query = {"$expr": {"$lte": ["$quantity", "$reorder_point"]}}
        if store_id:
            query["store_id"] = ObjectId(store_id)

        inventory_cursor = self.inventory_collection.find(query)
        inventory_items = await inventory_cursor.to_list(length=None)

        alerts = []
        for item in inventory_items:
            # Get product and store details
            product = await self.products_collection.find_one({"_id": item["product_id"]})
            store = await self.stores_collection.find_one({"_id": item["store_id"]})
            
            alert_type = "out_of_stock" if item["quantity"] == 0 else "low_stock"
            
            alerts.append(StockAlert(
                product_id=item["product_id"],
                store_id=item["store_id"],
                product_name=product["name"] if product else "Unknown",
                product_sku=product["sku"] if product else "Unknown",
                store_name=store["name"] if store else "Unknown",
                current_quantity=item["quantity"],
                reorder_point=item["reorder_point"],
                alert_type=alert_type
            ))

        return alerts

    def _serialize_product(self, product_doc: dict) -> ProductResponse:
        """Convert product document to ProductResponse"""
        return ProductResponse(
            id=str(product_doc["_id"]),
            sku=product_doc["sku"],
            name=product_doc["name"],
            description=product_doc.get("description"),
            category=product_doc["category"],
            subcategory=product_doc.get("subcategory"),
            brand=product_doc.get("brand"),
            unit=product_doc["unit"],
            cost_price=product_doc["cost_price"],
            selling_price=product_doc["selling_price"],
            min_stock_level=product_doc["min_stock_level"],
            supplier_id=product_doc.get("supplier_id"),
            barcode=product_doc.get("barcode"),
            specifications=product_doc.get("specifications", {}),
            images=product_doc.get("images", []),
            is_active=product_doc["is_active"],
            created_at=serialize_datetime(product_doc["created_at"])
        )

    async def _serialize_inventory_with_details(self, inventory_doc: dict) -> InventoryResponse:
        """Convert inventory document to InventoryResponse with product/store details"""
        # Get product details
        product = await self.products_collection.find_one({"_id": inventory_doc["product_id"]})
        store = await self.stores_collection.find_one({"_id": inventory_doc["store_id"]})
        
        available_quantity = inventory_doc["quantity"] - inventory_doc.get("reserved_quantity", 0)
        needs_reorder = inventory_doc["quantity"] <= inventory_doc.get("reorder_point", 0)
        
        return InventoryResponse(
            id=str(inventory_doc["_id"]),
            product_id=str(inventory_doc["product_id"]),
            store_id=str(inventory_doc["store_id"]),
            quantity=inventory_doc["quantity"],
            reserved_quantity=inventory_doc.get("reserved_quantity", 0),
            available_quantity=available_quantity,
            reorder_point=inventory_doc.get("reorder_point", 0),
            max_stock=inventory_doc.get("max_stock", 0),
            needs_reorder=needs_reorder,
            last_updated=serialize_datetime(inventory_doc["last_updated"]),
            product_name=product["name"] if product else None,
            product_sku=product["sku"] if product else None,
            store_name=store["name"] if store else None
        )