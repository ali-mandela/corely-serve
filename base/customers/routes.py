from fastapi import APIRouter, Depends, Request, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import Optional

from base.config import get_database
from base.utils import success_response
from base.rbac.decorators import require_permission
from .schemas import CreateCustomerRequest, UpdateCustomerRequest
from .service import CustomerService

customers_router = APIRouter()


def _get_org_slug(request: Request) -> str:
    slug = getattr(request.state, "org_slug", None)
    if not slug:
        raise ValueError("org_slug not found on request")
    return slug


@customers_router.post("/")
@require_permission("customers:create")
async def create_customer(
    request: Request,
    body: CreateCustomerRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Create a new customer for this organization."""
    slug = _get_org_slug(request)
    svc = CustomerService(db, slug)
    customer = await svc.create_customer(
        data=body.model_dump(), created_by=request.state.user.get("sub"),
    )
    return success_response(data=customer, message="Customer created", code=201)


@customers_router.get("/")
@require_permission("customers:read")
async def list_customers(
    request: Request,
    q: Optional[str] = Query(None),
    customer_type: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """List customers with optional search and type filter."""
    slug = _get_org_slug(request)
    svc = CustomerService(db, slug)
    customers, total = await svc.list_customers(
        query=q, customer_type=customer_type, limit=limit, offset=offset,
    )
    return success_response(
        data={"customers": customers, "total": total, "limit": limit, "offset": offset}
    )


@customers_router.get("/{customer_id}")
@require_permission("customers:read")
async def get_customer(
    request: Request, customer_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Get a single customer by ID."""
    slug = _get_org_slug(request)
    svc = CustomerService(db, slug)
    return success_response(data=await svc.get_customer(customer_id))


@customers_router.put("/{customer_id}")
@require_permission("customers:update")
async def update_customer(
    request: Request, customer_id: str, body: UpdateCustomerRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Update customer fields by ID."""
    slug = _get_org_slug(request)
    svc = CustomerService(db, slug)
    customer = await svc.update_customer(customer_id, body.model_dump(exclude_unset=True))
    return success_response(data=customer, message="Customer updated")


@customers_router.delete("/{customer_id}")
@require_permission("customers:delete")
async def delete_customer(
    request: Request, customer_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Soft-delete a customer by ID."""
    slug = _get_org_slug(request)
    svc = CustomerService(db, slug)
    result = await svc.delete_customer(customer_id)
    return success_response(data=result, message="Customer deleted")
