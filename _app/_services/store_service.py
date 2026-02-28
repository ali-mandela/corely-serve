from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId
from app._schemas.user_schema import UserResponse


from app._schemas.store_schema import (
    StoreCreate,
    StoreUpdate,
    StoreResponse,
    StoreList,
    StoreSettings,
    StoreTransfer,
    StoreStats,
)
from app.utils.exceptions import NotFoundError, DuplicateError, ValidationError
from app.utils.helpers import serialize_datetime, calculate_pagination


class StoreService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.stores_collection = db.stores
        self.users_collection = db.users
        self.employees_collection = db.employees
        self.inventory_collection = db.inventory
        self.products_collection = db.products
        self.sales_collection = db.sales

    async def create_store(
        self, store_data: StoreCreate, current_user: UserResponse
    ) -> StoreResponse:
        """Create a new store with organization and role validation"""

        # Check if user has permission to create stores
        if current_user.role not in ["admin", "admin"]:
            raise ValidationError("Insufficient permissions to create stores")

        # Check if store name already exists within the same organization
        existing_store = await self.stores_collection.find_one(
            {
                "name": store_data.name,
                "organization_id": ObjectId(current_user.organization_id),
            }
        )
        if existing_store:
            raise DuplicateError(
                "Store with this name already exists in your organization"
            )

        # Verify manager exists and belongs to same organization if provided
        # Handle "undefined" string from frontend
        manager_id = None
        if store_data.manager_id and store_data.manager_id != "undefined":
            try:
                manager_id = ObjectId(store_data.manager_id)
                manager = await self.users_collection.find_one(
                    {
                        "_id": manager_id,
                        "organization_id": ObjectId(current_user.organization_id),
                        "is_active": True,
                    }
                )
                if not manager:
                    raise ValidationError(
                        "Manager not found or not in your organization"
                    )
            except Exception:
                raise ValidationError("Invalid manager ID format")

        # Set default settings
        default_settings = {
            "tax_rate": 0.08,  # 8% default tax rate
            "currency": "USD",
            "timezone": "UTC",
            "business_hours": {
                "monday": {"open": "09:00", "close": "18:00"},
                "tuesday": {"open": "09:00", "close": "18:00"},
                "wednesday": {"open": "09:00", "close": "18:00"},
                "thursday": {"open": "09:00", "close": "18:00"},
                "friday": {"open": "09:00", "close": "18:00"},
                "saturday": {"open": "10:00", "close": "16:00"},
                "sunday": {"open": "closed", "close": "closed"},
            },
            "low_stock_threshold": 10,
            "auto_reorder": False,
            "loyalty_points_rate": 0.01,
        }

        # Merge with provided settings
        settings = {**default_settings, **store_data.settings}

        store_doc = {
            "name": store_data.name,
            "slug": store_data.slug,
            "description": store_data.description,
            "category": store_data.category or "general",
            "store_type": store_data.store_type or "retail",
            "address": store_data.address.dict(),
            "phone": store_data.phone,
            "email": store_data.email,
            "organization_id": ObjectId(
                current_user.organization_id
            ),  # Set organization_id from current user
            "manager_id": manager_id,
            "staff_ids": [],
            "store_hours": (
                store_data.store_hours.dict()
                if store_data.store_hours
                else {
                    "monday": {"open": "09:00", "close": "18:00"},
                    "tuesday": {"open": "09:00", "close": "18:00"},
                    "wednesday": {"open": "09:00", "close": "18:00"},
                    "thursday": {"open": "09:00", "close": "18:00"},
                    "friday": {"open": "09:00", "close": "18:00"},
                    "saturday": {"open": "10:00", "close": "16:00"},
                    "sunday": {"open": "12:00", "close": "16:00"},
                }
            ),
            "timezone": store_data.timezone or "UTC",
            "settings": settings,
            "pos_enabled": True,
            "inventory_enabled": True,
            "is_active": True,
            "is_main_store": False,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }

        result = await self.stores_collection.insert_one(store_doc)
        created_store = await self.stores_collection.find_one(
            {"_id": result.inserted_id}
        )

        return await self._serialize_store_with_details(created_store)

    async def get_store(self, store_id: str) -> StoreResponse:
        """Get store by ID"""
        try:
            store_doc = await self.stores_collection.find_one(
                {"_id": ObjectId(store_id)}
            )
            if not store_doc:
                raise NotFoundError("Store not found")
            return await self._serialize_store_with_details(store_doc)
        except Exception as e:
            if isinstance(e, NotFoundError):
                raise e
            raise ValidationError("Invalid store ID")

    async def update_store(
        self, store_id: str, store_data: StoreUpdate
    ) -> StoreResponse:
        """Update store"""
        try:
            update_data = {k: v for k, v in store_data.dict().items() if v is not None}
            if not update_data:
                raise ValidationError("No data provided for update")

            # Convert address to dict if provided
            if "address" in update_data:
                update_data["address"] = update_data["address"].dict()

            # Verify manager exists if being updated
            if "manager_id" in update_data and update_data["manager_id"]:
                manager = await self.users_collection.find_one(
                    {"_id": ObjectId(update_data["manager_id"])}
                )
                if not manager:
                    raise ValidationError("Manager not found")
                update_data["manager_id"] = ObjectId(update_data["manager_id"])

            result = await self.stores_collection.update_one(
                {"_id": ObjectId(store_id)}, {"$set": update_data}
            )

            if result.matched_count == 0:
                raise NotFoundError("Store not found")

            updated_store = await self.stores_collection.find_one(
                {"_id": ObjectId(store_id)}
            )
            return await self._serialize_store_with_details(updated_store)
        except Exception as e:
            if isinstance(e, (NotFoundError, ValidationError)):
                raise e
            raise ValidationError("Invalid store ID")

    async def delete_store(self, store_id: str) -> bool:
        """Soft delete store"""
        try:
            # Check if store has active inventory
            inventory_count = await self.inventory_collection.count_documents(
                {"store_id": ObjectId(store_id), "quantity": {"$gt": 0}}
            )

            if inventory_count > 0:
                raise ValidationError("Cannot delete store with active inventory")

            result = await self.stores_collection.update_one(
                {"_id": ObjectId(store_id)}, {"$set": {"is_active": False}}
            )
            return result.matched_count > 0
        except Exception as e:
            if isinstance(e, ValidationError):
                raise e
            return False

    async def list_stores(
        self,
        current_user: UserResponse,
        page: int = 1,
        per_page: int = 20,
        is_active: Optional[bool] = None,
        search: Optional[str] = None,
    ) -> StoreList:
        """List stores with pagination and filters"""
        skip = (page - 1) * per_page

        # Filter by organization (super_admin can see all stores)
        query = {}
        if current_user.role != "admin" and current_user.organization_id:
            query["organization_id"] = ObjectId(current_user.organization_id)

        if is_active is not None:
            query["is_active"] = is_active

        if search:
            query["$or"] = [
                {"name": {"$regex": search, "$options": "i"}},
                {"address.city": {"$regex": search, "$options": "i"}},
                {"address.state": {"$regex": search, "$options": "i"}},
            ]

        total = await self.stores_collection.count_documents(query)

        # Count active and inactive stores
        active_count = await self.stores_collection.count_documents(
            {**query, "is_active": True}
        )
        inactive_count = total - active_count

        stores_cursor = (
            self.stores_collection.find(query)
            .sort("created_at", -1)
            .skip(skip)
            .limit(per_page)
        )
        stores = await stores_cursor.to_list(length=per_page)

        serialized_stores = []
        for store in stores:
            serialized_stores.append(await self._serialize_store_with_details(store))

        return StoreList(
            stores=serialized_stores,
            active_count=active_count,
            inactive_count=inactive_count,
            **calculate_pagination(page, per_page, total),
        )

    async def update_store_settings(
        self, store_id: str, settings: StoreSettings
    ) -> StoreResponse:
        """Update store settings"""
        try:
            settings_data = {k: v for k, v in settings.dict().items() if v is not None}

            result = await self.stores_collection.update_one(
                {"_id": ObjectId(store_id)}, {"$set": {"settings": settings_data}}
            )

            if result.matched_count == 0:
                raise NotFoundError("Store not found")

            updated_store = await self.stores_collection.find_one(
                {"_id": ObjectId(store_id)}
            )
            return await self._serialize_store_with_details(updated_store)
        except Exception as e:
            if isinstance(e, NotFoundError):
                raise e
            raise ValidationError("Invalid store ID")

    async def transfer_inventory(
        self, transfer: StoreTransfer, user_id: str
    ) -> Dict[str, Any]:
        """Transfer inventory between stores"""
        # Check if both stores exist and are active
        from_store = await self.stores_collection.find_one(
            {"_id": ObjectId(transfer.from_store_id), "is_active": True}
        )
        to_store = await self.stores_collection.find_one(
            {"_id": ObjectId(transfer.to_store_id), "is_active": True}
        )

        if not from_store:
            raise NotFoundError("Source store not found or inactive")
        if not to_store:
            raise NotFoundError("Destination store not found or inactive")

        # Check if product exists
        product = await self.products_collection.find_one(
            {"_id": ObjectId(transfer.product_id)}
        )
        if not product:
            raise NotFoundError("Product not found")

        # Get source inventory
        from_inventory = await self.inventory_collection.find_one(
            {
                "product_id": ObjectId(transfer.product_id),
                "store_id": ObjectId(transfer.from_store_id),
            }
        )

        if not from_inventory:
            raise ValidationError("No inventory found for this product at source store")

        if from_inventory["quantity"] < transfer.quantity:
            raise ValidationError("Insufficient inventory at source store")

        # Start transaction
        async with await self.db.client.start_session() as session:
            async with session.start_transaction():
                # Reduce quantity at source store
                await self.inventory_collection.update_one(
                    {
                        "product_id": ObjectId(transfer.product_id),
                        "store_id": ObjectId(transfer.from_store_id),
                    },
                    {
                        "$inc": {"quantity": -transfer.quantity},
                        "$set": {"last_updated": datetime.utcnow()},
                    },
                    session=session,
                )

                # Check if destination store has inventory record
                to_inventory = await self.inventory_collection.find_one(
                    {
                        "product_id": ObjectId(transfer.product_id),
                        "store_id": ObjectId(transfer.to_store_id),
                    },
                    session=session,
                )

                if to_inventory:
                    # Update existing inventory
                    await self.inventory_collection.update_one(
                        {
                            "product_id": ObjectId(transfer.product_id),
                            "store_id": ObjectId(transfer.to_store_id),
                        },
                        {
                            "$inc": {"quantity": transfer.quantity},
                            "$set": {"last_updated": datetime.utcnow()},
                        },
                        session=session,
                    )
                else:
                    # Create new inventory record
                    await self.inventory_collection.insert_one(
                        {
                            "product_id": ObjectId(transfer.product_id),
                            "store_id": ObjectId(transfer.to_store_id),
                            "quantity": transfer.quantity,
                            "reserved_quantity": 0,
                            "reorder_point": from_inventory.get("reorder_point", 0),
                            "max_stock": from_inventory.get("max_stock", 0),
                            "last_updated": datetime.utcnow(),
                        },
                        session=session,
                    )

                # Log the transfer
                transfer_log = {
                    "product_id": ObjectId(transfer.product_id),
                    "from_store_id": ObjectId(transfer.from_store_id),
                    "to_store_id": ObjectId(transfer.to_store_id),
                    "quantity": transfer.quantity,
                    "reason": transfer.reason,
                    "notes": transfer.notes,
                    "user_id": ObjectId(user_id),
                    "created_at": datetime.utcnow(),
                }
                await self.db.inventory_transfers.insert_one(
                    transfer_log, session=session
                )

        return {
            "message": "Inventory transferred successfully",
            "transfer": {
                "product_name": product["name"],
                "from_store": from_store["name"],
                "to_store": to_store["name"],
                "quantity": transfer.quantity,
                "reason": transfer.reason,
            },
        }

    async def get_store_stats(self, store_id: str) -> StoreStats:
        """Get comprehensive store statistics"""
        store = await self.stores_collection.find_one({"_id": ObjectId(store_id)})
        if not store:
            raise NotFoundError("Store not found")

        # Get today's date range
        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=today_start.weekday())
        month_start = today_start.replace(day=1)

        # Inventory stats
        inventory_pipeline = [
            {"$match": {"store_id": ObjectId(store_id)}},
            {
                "$lookup": {
                    "from": "products",
                    "localField": "product_id",
                    "foreignField": "_id",
                    "as": "product",
                }
            },
            {"$unwind": "$product"},
            {
                "$group": {
                    "_id": None,
                    "total_products": {"$sum": 1},
                    "total_value": {
                        "$sum": {"$multiply": ["$quantity", "$product.cost_price"]}
                    },
                    "low_stock_items": {
                        "$sum": {
                            "$cond": [{"$lte": ["$quantity", "$reorder_point"]}, 1, 0]
                        }
                    },
                    "out_of_stock_items": {
                        "$sum": {"$cond": [{"$eq": ["$quantity", 0]}, 1, 0]}
                    },
                }
            },
        ]

        inventory_stats_result = await self.inventory_collection.aggregate(
            inventory_pipeline
        ).to_list(length=1)
        inventory_stats = (
            inventory_stats_result[0]
            if inventory_stats_result
            else {
                "total_products": 0,
                "total_value": 0,
                "low_stock_items": 0,
                "out_of_stock_items": 0,
            }
        )

        # Sales stats for different periods
        periods = {
            "today": {"$gte": today_start},
            "this_week": {"$gte": week_start},
            "this_month": {"$gte": month_start},
        }

        sales_stats = {}
        for period_name, date_filter in periods.items():
            sales_pipeline = [
                {"$match": {"store_id": ObjectId(store_id), "sale_date": date_filter}},
                {
                    "$group": {
                        "_id": None,
                        "sales_count": {"$sum": 1},
                        "sales_amount": {"$sum": "$total_amount"},
                    }
                },
            ]

            period_result = await self.sales_collection.aggregate(
                sales_pipeline
            ).to_list(length=1)
            sales_stats[period_name] = (
                period_result[0]
                if period_result
                else {"sales_count": 0, "sales_amount": 0}
            )

        # Top products
        top_products_pipeline = [
            {
                "$match": {
                    "store_id": ObjectId(store_id),
                    "sale_date": {"$gte": month_start},
                }
            },
            {"$unwind": "$items"},
            {
                "$group": {
                    "_id": "$items.product_id",
                    "total_quantity": {"$sum": "$items.quantity"},
                    "total_revenue": {"$sum": "$items.total"},
                }
            },
            {"$sort": {"total_quantity": -1}},
            {"$limit": 5},
        ]

        top_products_result = await self.sales_collection.aggregate(
            top_products_pipeline
        ).to_list(length=5)

        # Enrich with product details
        top_products = []
        for item in top_products_result:
            product = await self.products_collection.find_one({"_id": item["_id"]})
            top_products.append(
                {
                    "product_name": product["name"] if product else "Unknown",
                    "total_quantity": item["total_quantity"],
                    "total_revenue": float(item["total_revenue"]),
                }
            )

        # Employee count
        employee_count = await self.employees_collection.count_documents(
            {
                "$or": [
                    {"store_id": ObjectId(store_id)},
                    {"additional_store_ids": ObjectId(store_id)},
                ],
                "is_active": True,
            }
        )

        return StoreStats(
            store_id=ObjectId(store_id),
            store_name=store["name"],
            total_products=inventory_stats["total_products"],
            total_inventory_value=float(inventory_stats["total_value"]),
            low_stock_items=inventory_stats["low_stock_items"],
            out_of_stock_items=inventory_stats["out_of_stock_items"],
            today_sales={
                "count": sales_stats["today"]["sales_count"],
                "amount": float(sales_stats["today"]["sales_amount"]),
            },
            this_week_sales={
                "count": sales_stats["this_week"]["sales_count"],
                "amount": float(sales_stats["this_week"]["sales_amount"]),
            },
            this_month_sales={
                "count": sales_stats["this_month"]["sales_count"],
                "amount": float(sales_stats["this_month"]["sales_amount"]),
            },
            top_products=top_products,
            employee_count=employee_count,
        )

    async def _serialize_store_with_details(self, store_doc: dict) -> StoreResponse:
        """Convert store document to StoreResponse with calculated fields"""
        try:
            # Get manager details safely
            manager = None
            if store_doc.get("manager_id"):
                try:
                    manager = await self.users_collection.find_one(
                        {"_id": store_doc["manager_id"]}
                    )
                except Exception:
                    pass  # Manager lookup failed, continue without manager details

            # Calculate employee count safely (use users collection instead of employees)
            employee_count = 0
            try:
                employee_count = await self.users_collection.count_documents(
                    {
                        "store_ids": store_doc["_id"],
                        "is_active": True,
                    }
                )
            except Exception:
                pass  # Employee count failed, use 0

            return StoreResponse(
                id=str(store_doc["_id"]),
                organization_id=str(store_doc.get("organization_id", "")),
                name=store_doc["name"],
                slug=store_doc.get("slug", ""),
                description=store_doc.get("description"),
                category=store_doc.get("category", "general"),
                store_type=store_doc.get("store_type", "retail"),
                address=store_doc["address"],
                phone=store_doc.get("phone", ""),
                email=store_doc.get("email"),
                manager_id=(
                    str(store_doc["manager_id"])
                    if store_doc.get("manager_id")
                    else None
                ),
                staff_ids=[str(id) for id in store_doc.get("staff_ids", [])],
                store_hours=self._normalize_store_hours(
                    store_doc.get("store_hours", {})
                ),
                timezone=store_doc.get("timezone", "UTC"),
                settings=store_doc.get("settings", {}),
                pos_enabled=store_doc.get("pos_enabled", True),
                inventory_enabled=store_doc.get("inventory_enabled", True),
                is_active=store_doc.get("is_active", True),
                is_main_store=store_doc.get("is_main_store", False),
                created_at=serialize_datetime(store_doc.get("created_at"))
                or datetime.utcnow().isoformat(),
                updated_at=serialize_datetime(store_doc.get("updated_at"))
                or datetime.utcnow().isoformat(),
                manager_name=(
                    manager.get("full_name") or manager.get("username")
                    if manager
                    else None
                ),
                employee_count=employee_count,
                total_inventory_value=0.0,  # Simplified for now
                today_sales_count=0,  # Simplified for now
                today_sales_amount=0.0,  # Simplified for now
            )
        except Exception as e:
            # Log the error and raise a more specific error
            print(f"Store serialization error: {e}")
            print(f"Store doc: {store_doc}")
            raise ValidationError(f"Failed to serialize store data: {str(e)}")

    async def get_user_stores(self, current_user: UserResponse) -> List[StoreResponse]:
        """Get stores accessible to the current user"""
        query = {}

        # Super admin can see all stores
        if current_user.role == "admin":
            query = {}
        # Admin can see stores in their organization
        elif current_user.role == "admin" and current_user.organization_id:
            query["organization_id"] = ObjectId(current_user.organization_id)
        # Manager/Employee can see stores they're assigned to
        elif (
            current_user.role in ["manager", "employee"]
            and current_user.organization_id
        ):
            query = {
                "organization_id": ObjectId(current_user.organization_id),
                "$or": [
                    {"manager_id": ObjectId(current_user.id)},
                    {"staff_ids": {"$in": [ObjectId(current_user.id)]}},
                ],
            }
        else:
            # If no valid conditions, return empty list
            return []

        stores = (
            await self.stores_collection.find(query)
            .sort("created_at", -1)
            .to_list(length=None)
        )

        serialized_stores = []
        for store in stores:
            try:
                serialized_stores.append(
                    await self._serialize_store_with_details(store)
                )
            except Exception as e:
                print(f"Error serializing store {store.get('_id')}: {e}")
                continue

        return serialized_stores

    def _normalize_store_hours(self, store_hours: dict) -> dict:
        """Normalize store hours data to match expected schema"""
        if not store_hours:
            # Return default store hours
            return {
                "monday": {"open": "09:00", "close": "18:00"},
                "tuesday": {"open": "09:00", "close": "18:00"},
                "wednesday": {"open": "09:00", "close": "18:00"},
                "thursday": {"open": "09:00", "close": "18:00"},
                "friday": {"open": "09:00", "close": "18:00"},
                "saturday": {"open": "10:00", "close": "16:00"},
                "sunday": {"open": "12:00", "close": "16:00"},
            }

        normalized = {}
        days = [
            "monday",
            "tuesday",
            "wednesday",
            "thursday",
            "friday",
            "saturday",
            "sunday",
        ]

        for day in days:
            if day in store_hours:
                day_hours = store_hours[day]
                if isinstance(day_hours, dict):
                    # Handle case where data has is_open boolean
                    if "is_open" in day_hours and isinstance(
                        day_hours.get("is_open"), bool
                    ):
                        if day_hours["is_open"]:
                            normalized[day] = {
                                "open": day_hours.get("open", "09:00"),
                                "close": day_hours.get("close", "18:00"),
                            }
                        else:
                            normalized[day] = {"open": "closed", "close": "closed"}
                    else:
                        # Already in correct format
                        normalized[day] = {
                            "open": str(day_hours.get("open", "09:00")),
                            "close": str(day_hours.get("close", "18:00")),
                        }
                else:
                    # Default for this day
                    default_times = {
                        "monday": "09:00",
                        "tuesday": "09:00",
                        "wednesday": "09:00",
                        "thursday": "09:00",
                        "friday": "09:00",
                        "saturday": "10:00",
                        "sunday": "12:00",
                    }
                    normalized[day] = {
                        "open": default_times.get(day, "09:00"),
                        "close": (
                            "18:00"
                            if day != "saturday" and day != "sunday"
                            else "16:00"
                        ),
                    }
            else:
                # Default for this day
                default_times = {
                    "monday": "09:00",
                    "tuesday": "09:00",
                    "wednesday": "09:00",
                    "thursday": "09:00",
                    "friday": "09:00",
                    "saturday": "10:00",
                    "sunday": "12:00",
                }
                normalized[day] = {
                    "open": default_times.get(day, "09:00"),
                    "close": (
                        "18:00" if day != "saturday" and day != "sunday" else "16:00"
                    ),
                }

        return normalized
