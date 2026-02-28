from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from motor.motor_asyncio import AsyncIOMotorDatabase

from app._core.database import get_database
from app._services.inventory_service import InventoryService
from app._schemas.product_schema import (
    ProductCreate,
    ProductUpdate,
    ProductResponse,
    ProductList,
)
from app._schemas.user_schema import UserResponse
from app._services.auth_service import get_current_user
from app.utils.exceptions import NotFoundError, DuplicateError, ValidationError

# Enterprise security imports
from app._core.abac.decorators import (
    require_permission,
    require_read_permission,
    require_write_permission,
)
from app._core.tenant_isolation import (
    get_tenant_context,
    TenantContext,
    require_tenant_isolation,
)
from app._core.audit.logger import log_data_event

router = APIRouter()


async def get_inventory_service(
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> InventoryService:
    return InventoryService(db)


@router.post("/", response_model=ProductResponse, status_code=status.HTTP_201_CREATED)
@require_permission("product", "create")
@require_tenant_isolation()
async def create_product(
    product_data: ProductCreate,
    request: Request = None,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    inventory_service: InventoryService = Depends(get_inventory_service),
):
    """Create a new product"""
    try:
        return await inventory_service.create_product(product_data, current_user)
    except DuplicateError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)
        )


@router.get("/", response_model=ProductList)
@require_read_permission("product")
@require_tenant_isolation()
async def list_products(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    category: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    store_id: Optional[str] = Query(None),
    request: Request = None,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    inventory_service: InventoryService = Depends(get_inventory_service),
):
    """List products with pagination and filters"""
    return await inventory_service.list_products(
        page=page,
        per_page=per_page,
        category=category,
        search=search,
        store_id=store_id,
    )


@router.get("/{product_id}", response_model=ProductResponse)
async def get_product(
    product_id: str,
    current_user: UserResponse = Depends(get_current_user),
    inventory_service: InventoryService = Depends(get_inventory_service),
):
    """Get product by ID"""
    try:
        return await inventory_service.get_product(product_id)
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)
        )


@router.put("/{product_id}", response_model=ProductResponse)
async def update_product(
    product_id: str,
    product_data: ProductUpdate,
    current_user: UserResponse = Depends(get_current_user),
    inventory_service: InventoryService = Depends(get_inventory_service),
):
    """Update product"""
    try:
        return await inventory_service.update_product(product_id, product_data)
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)
        )


@router.delete("/{product_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_product(
    product_id: str,
    current_user: UserResponse = Depends(get_current_user),
    inventory_service: InventoryService = Depends(get_inventory_service),
):
    """Delete product (soft delete)"""
    success = await inventory_service.delete_product(product_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Product not found"
        )
