from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app._core.database import get_database
from app._services.inventory_service import InventoryService
from app._schemas.inventory_schema import (
    InventoryCreate, InventoryUpdate, InventoryResponse, InventoryList,
    InventoryAdjustment, InventoryTransfer, StockAlert
)
from app._schemas.user_schema import UserResponse
from app._services.auth_service import get_current_user
from app.utils.exceptions import NotFoundError, DuplicateError, ValidationError

router = APIRouter()


async def get_inventory_service(db: AsyncIOMotorDatabase = Depends(get_database)) -> InventoryService:
    return InventoryService(db)


@router.post("/", response_model=InventoryResponse, status_code=status.HTTP_201_CREATED)
async def create_inventory(
    inventory_data: InventoryCreate,
    current_user: UserResponse = Depends(get_current_user),
    inventory_service: InventoryService = Depends(get_inventory_service)
):
    """Create inventory record for a product at a store"""
    try:
        return await inventory_service.create_inventory(inventory_data, current_user)
    except DuplicateError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


@router.get("/store/{store_id}", response_model=InventoryList)
async def get_store_inventory(
    store_id: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    current_user: UserResponse = Depends(get_current_user),
    inventory_service: InventoryService = Depends(get_inventory_service)
):
    """Get inventory for a specific store"""
    return await inventory_service.get_store_inventory(store_id, current_user, page, per_page)


@router.put("/{inventory_id}", response_model=InventoryResponse)
async def update_inventory(
    inventory_id: str,
    inventory_data: InventoryUpdate,
    current_user: UserResponse = Depends(get_current_user),
    inventory_service: InventoryService = Depends(get_inventory_service)
):
    """Update inventory record"""
    try:
        return await inventory_service.update_inventory(inventory_id, inventory_data)
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


@router.post("/adjust", response_model=InventoryResponse)
async def adjust_inventory(
    adjustment: InventoryAdjustment,
    current_user: UserResponse = Depends(get_current_user),
    inventory_service: InventoryService = Depends(get_inventory_service)
):
    """Adjust inventory quantity"""
    try:
        return await inventory_service.adjust_inventory(adjustment, str(current_user.id))
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


@router.get("/alerts", response_model=List[StockAlert])
async def get_stock_alerts(
    store_id: Optional[str] = Query(None),
    current_user: UserResponse = Depends(get_current_user),
    inventory_service: InventoryService = Depends(get_inventory_service)
):
    """Get low stock alerts"""
    return await inventory_service.get_low_stock_alerts(store_id)


@router.post("/transfer", status_code=status.HTTP_200_OK)
async def transfer_inventory(
    transfer: InventoryTransfer,
    current_user: UserResponse = Depends(get_current_user),
    inventory_service: InventoryService = Depends(get_inventory_service)
):
    """Transfer inventory between stores"""
    # This would be implemented as a transaction
    # For now, we'll return a simple response
    return {"message": "Inventory transfer functionality will be implemented with transactions"}