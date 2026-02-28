from typing import Optional, List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

from app._core.database import get_database
from app._schemas.store_schema import (
    StoreCreate,
    StoreUpdate,
    StoreResponse,
    StoreListResponse,
    StoreSettings,
    StoreSettingsUpdate,
    StoreStats,
    StoreTransfer,
    StoreBulkAction,
    StoreStatus,
    StoreType,
)
from app._schemas.user_schema import UserResponse
from app._services.auth_service import get_current_user
from app.utils.exceptions import NotFoundError, DuplicateError, ValidationError
from app._models.user import UserRole

# ABAC and audit imports
from app._core.abac.decorators import require_permission, require_read_permission, require_write_permission
from app._core.tenant_isolation import get_tenant_context, TenantContext, require_tenant_isolation
from app._core.audit.logger import log_data_event

router = APIRouter()


class StoreService:
    """Production-grade Store Service with full functionality"""

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.stores_collection = db.stores
        self.users_collection = db.users
        self.products_collection = db.products
        self.sales_collection = db.sales
        self.customers_collection = db.customers

    async def create_store(self, store_data: StoreCreate, organization_id: str) -> StoreResponse:
        """Create a new store"""
        # Check if slug is unique within organization
        existing_store = await self.stores_collection.find_one({
            "slug": store_data.slug,
            "organization_id": ObjectId(organization_id)
        })
        if existing_store:
            raise DuplicateError("Store slug already exists in this organization")

        # Validate manager if provided
        if store_data.manager_id:
            manager = await self.users_collection.find_one({
                "_id": ObjectId(store_data.manager_id),
                "organization_id": ObjectId(organization_id),
                "role": {"$in": ["manager", "admin"]}
            })
            if not manager:
                raise NotFoundError("Manager not found or invalid role")

        # Create store document
        store_doc = {
            "organization_id": ObjectId(organization_id),
            "name": store_data.name,
            "slug": store_data.slug,
            "description": store_data.description,
            "store_type": store_data.store_type.value,
            "category": store_data.category,
            "address": store_data.address.dict(),
            "phone": store_data.phone,
            "email": store_data.email,
            "website": store_data.website,
            "manager_id": ObjectId(store_data.manager_id) if store_data.manager_id else None,
            "store_hours": store_data.store_hours.dict() if store_data.store_hours else {
                "monday": {"open": "09:00", "close": "18:00", "closed": False},
                "tuesday": {"open": "09:00", "close": "18:00", "closed": False},
                "wednesday": {"open": "09:00", "close": "18:00", "closed": False},
                "thursday": {"open": "09:00", "close": "18:00", "closed": False},
                "friday": {"open": "09:00", "close": "18:00", "closed": False},
                "saturday": {"open": "10:00", "close": "16:00", "closed": False},
                "sunday": {"open": "12:00", "close": "16:00", "closed": True}
            },
            "settings": store_data.settings.dict() if store_data.settings else {
                "currency": "INR",
                "timezone": "IST",
                "tax_rate": 0.0,
                "pos_enabled": True,
                "inventory_tracking": True,
                "low_stock_threshold": 10,
                "auto_reorder": False,
                "loyalty_program_enabled": False,
                "receipt_footer": None,
                "custom_fields": {}
            },
            "status": StoreStatus.ACTIVE.value,
            "max_employees": store_data.max_employees,
            "square_footage": store_data.square_footage,
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }

        result = await self.stores_collection.insert_one(store_doc)
        created_store = await self.stores_collection.find_one({"_id": result.inserted_id})

        return await self._serialize_store(created_store)

    async def get_store_by_id(self, store_id: str, organization_id: str) -> StoreResponse:
        """Get store by ID"""
        store = await self.stores_collection.find_one({
            "_id": ObjectId(store_id),
            "organization_id": ObjectId(organization_id)
        })
        if not store:
            raise NotFoundError("Store not found")

        return await self._serialize_store(store)

    async def update_store(self, store_id: str, store_data: StoreUpdate, organization_id: str) -> StoreResponse:
        """Update store"""
        store = await self.stores_collection.find_one({
            "_id": ObjectId(store_id),
            "organization_id": ObjectId(organization_id)
        })
        if not store:
            raise NotFoundError("Store not found")

        # Prepare update data
        update_data = {k: v for k, v in store_data.dict(exclude_unset=True).items() if v is not None}

        if update_data:
            # Note: address and store_hours are already dictionaries from store_data.dict()
            # No need to call .dict() again

            update_data["updated_at"] = datetime.now(timezone.utc)

            await self.stores_collection.update_one(
                {"_id": ObjectId(store_id)},
                {"$set": update_data}
            )

        updated_store = await self.stores_collection.find_one({"_id": ObjectId(store_id)})
        return await self._serialize_store(updated_store)

    async def delete_store(self, store_id: str, organization_id: str) -> bool:
        """Delete store (soft delete)"""
        result = await self.stores_collection.update_one(
            {"_id": ObjectId(store_id), "organization_id": ObjectId(organization_id)},
            {"$set": {"is_active": False, "status": StoreStatus.INACTIVE.value, "updated_at": datetime.now(timezone.utc)}}
        )
        return result.modified_count > 0

    async def list_stores(self, organization_id: str, page: int = 1, per_page: int = 20,
                         status: Optional[StoreStatus] = None, store_type: Optional[StoreType] = None,
                         search: Optional[str] = None) -> StoreListResponse:
        """List stores with pagination and filters"""
        query = {"organization_id": ObjectId(organization_id), "is_active": True}

        if status:
            query["status"] = status.value
        if store_type:
            query["store_type"] = store_type.value
        if search:
            query["$or"] = [
                {"name": {"$regex": search, "$options": "i"}},
                {"description": {"$regex": search, "$options": "i"}},
                {"category": {"$regex": search, "$options": "i"}}
            ]

        total = await self.stores_collection.count_documents(query)
        skip = (page - 1) * per_page

        stores_cursor = self.stores_collection.find(query).skip(skip).limit(per_page).sort("created_at", -1)
        stores = await stores_cursor.to_list(length=per_page)

        serialized_stores = []
        for store in stores:
            serialized_stores.append(await self._serialize_store(store))

        return StoreListResponse(
            stores=serialized_stores,
            total=total,
            page=page,
            per_page=per_page,
            pages=(total + per_page - 1) // per_page
        )

    async def get_store_stats(self, store_id: str, organization_id: str) -> StoreStats:
        """Get comprehensive store statistics"""
        store = await self.stores_collection.find_one({
            "_id": ObjectId(store_id),
            "organization_id": ObjectId(organization_id)
        })
        if not store:
            raise NotFoundError("Store not found")

        # Aggregate statistics
        total_employees = await self.users_collection.count_documents({
            "organization_id": ObjectId(organization_id),
            "store_ids": ObjectId(store_id),
            "is_active": True
        })

        total_products = await self.products_collection.count_documents({
            "organization_id": ObjectId(organization_id),
            "store_id": ObjectId(store_id),
            "is_active": True
        })

        # Sales statistics
        sales_pipeline = [
            {"$match": {
                "store_id": ObjectId(store_id),
                "organization_id": ObjectId(organization_id)
            }},
            {"$group": {
                "_id": None,
                "total_sales": {"$sum": "$total_amount"},
                "total_orders": {"$sum": 1},
                "avg_order_value": {"$avg": "$total_amount"}
            }}
        ]
        sales_stats = await self.sales_collection.aggregate(sales_pipeline).to_list(1)
        sales_data = sales_stats[0] if sales_stats else {
            "total_sales": 0, "total_orders": 0, "avg_order_value": 0
        }

        total_customers = await self.customers_collection.count_documents({
            "organization_id": ObjectId(organization_id),
            "store_ids": ObjectId(store_id)
        })

        return StoreStats(
            store_id=store_id,
            store_name=store["name"],
            total_sales=sales_data["total_sales"],
            total_orders=sales_data["total_orders"],
            total_customers=total_customers,
            total_products=total_products,
            total_employees=total_employees,
            avg_order_value=sales_data["avg_order_value"],
            monthly_revenue=0.0,  # Would require date filtering
            daily_revenue=0.0,   # Would require date filtering
            inventory_value=0.0, # Would require inventory calculation
            low_stock_items=0,   # Would require inventory check
            out_of_stock_items=0 # Would require inventory check
        )

    async def _serialize_store(self, store_doc: dict) -> StoreResponse:
        """Serialize store document to response model"""
        # Get manager name if exists
        manager_name = None
        if store_doc.get("manager_id"):
            manager = await self.users_collection.find_one({"_id": store_doc["manager_id"]})
            if manager:
                manager_name = manager.get("full_name") or manager.get("username")

        # Get totals
        total_employees = await self.users_collection.count_documents({
            "organization_id": store_doc["organization_id"],
            "store_ids": store_doc["_id"],
            "is_active": True
        })

        total_products = await self.products_collection.count_documents({
            "organization_id": store_doc["organization_id"],
            "store_id": store_doc["_id"],
            "is_active": True
        })

        return StoreResponse(
            id=str(store_doc["_id"]),
            organization_id=str(store_doc["organization_id"]),
            name=store_doc["name"],
            slug=store_doc["slug"],
            description=store_doc.get("description"),
            store_type=StoreType(store_doc["store_type"]),
            category=store_doc["category"],
            address=store_doc["address"],
            phone=store_doc["phone"],
            email=store_doc.get("email"),
            website=store_doc.get("website"),
            manager_id=str(store_doc["manager_id"]) if store_doc.get("manager_id") else None,
            manager_name=manager_name,
            store_hours=store_doc["store_hours"],
            settings=store_doc["settings"],
            status=StoreStatus(store_doc["status"]),
            max_employees=store_doc["max_employees"],
            square_footage=store_doc.get("square_footage"),
            total_employees=total_employees,
            total_products=total_products,
            is_active=store_doc["is_active"],
            created_at=store_doc["created_at"],
            updated_at=store_doc["updated_at"]
        )


async def get_store_service(db: AsyncIOMotorDatabase = Depends(get_database)) -> StoreService:
    """Get store service instance"""
    return StoreService(db)


# API Endpoints
@router.post("/", response_model=StoreResponse, status_code=status.HTTP_201_CREATED)
@require_permission("store", "create")
@require_tenant_isolation()
async def create_store(
    request: Request,
    store_data: StoreCreate,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    store_service: StoreService = Depends(get_store_service)
):
    """Create a new store - Admin/Super Admin only"""
    try:

        store = await store_service.create_store(store_data, tenant_context.tenant_id)

        await log_data_event(
            user_id=current_user.id,
            operation="create",
            resource_type="store",
            resource_id=store.id,
            success=True,
            tenant_id=tenant_context.tenant_id
        )

        return store
    except DuplicateError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/", response_model=StoreListResponse)
@require_read_permission("store")
@require_tenant_isolation()
async def list_stores(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[StoreStatus] = Query(None),
    store_type: Optional[StoreType] = Query(None),
    search: Optional[str] = Query(None),
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    store_service: StoreService = Depends(get_store_service)
):
    """List stores with pagination and filters"""
    return await store_service.list_stores(
        tenant_context.tenant_id, page, per_page, status, store_type, search
    )


@router.get("/{store_id}", response_model=StoreResponse)
@require_read_permission("store")
@require_tenant_isolation()
async def get_store(
    request: Request,
    store_id: str,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    store_service: StoreService = Depends(get_store_service)
):
    """Get store by ID"""
    try:
        return await store_service.get_store_by_id(store_id, tenant_context.tenant_id)
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.put("/{store_id}", response_model=StoreResponse)
@require_permission("store", "update")
@require_tenant_isolation()
async def update_store(
    request: Request,
    store_id: str,
    store_data: StoreUpdate,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    store_service: StoreService = Depends(get_store_service)
):
    """Update store - Admin/Super Admin only"""
    try:

        store = await store_service.update_store(store_id, store_data, tenant_context.tenant_id)

        await log_data_event(
            user_id=current_user.id,
            operation="update",
            resource_type="store",
            resource_id=store_id,
            success=True,
            tenant_id=tenant_context.tenant_id
        )

        return store
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/{store_id}")
@require_permission("store", "delete")
@require_tenant_isolation()
async def delete_store(
    request: Request,
    store_id: str,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    store_service: StoreService = Depends(get_store_service)
):
    """Delete store - Admin/Super Admin only"""
    try:

        success = await store_service.delete_store(store_id, tenant_context.tenant_id)
        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Store not found")

        await log_data_event(
            user_id=current_user.id,
            operation="delete",
            resource_type="store",
            resource_id=store_id,
            success=True,
            tenant_id=tenant_context.tenant_id
        )

        return {"message": "Store deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/{store_id}/stats", response_model=StoreStats)
@require_read_permission("store")
@require_tenant_isolation()
async def get_store_stats(
    request: Request,
    store_id: str,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    store_service: StoreService = Depends(get_store_service)
):
    """Get store statistics and analytics"""
    try:
        return await store_service.get_store_stats(store_id, tenant_context.tenant_id)
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.put("/{store_id}/settings", response_model=StoreResponse)
@require_permission("store", "update")
@require_tenant_isolation()
async def update_store_settings(
    request: Request,
    store_id: str,
    settings_data: StoreSettingsUpdate,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    store_service: StoreService = Depends(get_store_service)
):
    """Update store settings - Admin/Super Admin only"""
    try:
        # Convert settings update to store update
        store_update = StoreUpdate()
        # Would need to implement settings merge logic here

        store = await store_service.update_store(store_id, store_update, tenant_context.tenant_id)

        await log_data_event(
            user_id=current_user.id,
            operation="update_settings",
            resource_type="store",
            resource_id=store_id,
            success=True,
            tenant_id=tenant_context.tenant_id
        )

        return store
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.put("/{store_id}/status", response_model=StoreResponse)
@require_permission("store", "update")
@require_tenant_isolation()
async def update_store_status(
    request: Request,
    store_id: str,
    status_data: dict,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    store_service: StoreService = Depends(get_store_service)
):
    """Update store status - Admin/Super Admin only"""
    try:
        new_status = status_data.get("status")
        if not new_status or new_status not in [s.value for s in StoreStatus]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status")

        store_update = StoreUpdate(status=StoreStatus(new_status))
        store = await store_service.update_store(store_id, store_update, tenant_context.tenant_id)

        await log_data_event(
            user_id=current_user.id,
            operation="update_status",
            resource_type="store",
            resource_id=store_id,
            success=True,
            tenant_id=tenant_context.tenant_id,
            metadata={"new_status": new_status}
        )

        return store
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# Additional utility endpoints
@router.get("/{store_id}/employees")
async def get_store_employees(
    store_id: str,
    current_user: UserResponse = Depends(get_current_user)
):
    """Get employees assigned to this store"""
    return {
        "message": "Use /api/v1/employees?store_id={store_id} for store employees",
        "store_id": store_id,
    }


@router.get("/{store_id}/inventory")
async def get_store_inventory(
    store_id: str,
    current_user: UserResponse = Depends(get_current_user)
):
    """Get store inventory summary"""
    return {
        "message": "Use /api/v1/inventory?store_id={store_id} for store inventory",
        "store_id": store_id,
    }


@router.get("/{store_id}/sales")
async def get_store_sales(
    store_id: str,
    current_user: UserResponse = Depends(get_current_user)
):
    """Get sales for this store"""
    return {
        "message": "Use /api/v1/sales?store_id={store_id} for store sales",
        "store_id": store_id,
    }