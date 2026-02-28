from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from app.core.config.database import get_database
from app.service.customer_service import CustomerService
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.schema.customer_schema import AddCustomer
from app.utils.helpers import success_response, error_response
from bson import ObjectId
from typing import Optional

customer = APIRouter()


async def get_service(
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> CustomerService:
    return CustomerService(db)


@customer.post("")
async def create_customer(
    request: Request,
    customer_data: AddCustomer,
    db: AsyncIOMotorDatabase = Depends(get_database),
    customer_service: CustomerService = Depends(get_service),
):
    """Createa a new Customer"""
    c = request.state.user
    org = await db["organizations"].find_one({"slug": c.get("org_slug")})
    if org is None:
        error_response(message="Organization not found", code=404)
    else:
        c["organization_id"] = str(org["_id"])

    try:
        result = await customer_service.create_customer(customer_data, c)
        return success_response(
            code=201, message="Customer created successfully", data=result
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        return error_response(
            message=f"Failed to create customer", data=str(e), code=500
        )


@customer.get("/{id}")
async def get_customer(
    id: str, customer_service: CustomerService = Depends(get_service)
):
    if not ObjectId.is_valid(id):
        return error_response(message="Invalid customer ID", code=400)

    customer = await customer_service.get_customer_by_id(ObjectId(id))

    if not customer:
        return error_response(message="Customer not found", code=404)

    return success_response(
        code=200, message="Customer fetched successfully", data=customer
    )


@customer.delete("/{id}")
async def delete_customer(
    id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
    customer_service: CustomerService = Depends(get_service),
):
    """Soft delete a customer by ID"""

    if not ObjectId.is_valid(id):
        return error_response(message="Invalid customer ID", code=400)

    try:
        result = await customer_service.delete_customer(id)
        return result  # Already returns success_response inside service
    except HTTPException as e:
        raise e
    except Exception as e:
        return error_response(
            message="Failed to delete customer", data=str(e), code=500
        )


@customer.get("")
async def list_customers(
    query: Optional[str] = Query(
        None, description="Search term for name, email, or phone"
    ),
    limit: int = Query(10, ge=1, le=100, description="Number of customers per page"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: AsyncIOMotorDatabase = Depends(get_database),
    customer_service: CustomerService = Depends(get_service),
):
    """List customers with optional search and pagination"""
    try:
        customers_data, total = await customer_service.list_customers(
            query=query, limit=limit, offset=offset
        )
        return success_response(
            message="Customers fetched successfully",
            data={
                "results": customers_data,
                "pagination": {
                    "limit": limit,
                    "offset": offset,
                    "total": total,
                    "has_next": total > offset + limit,
                },
            },
        )
    except Exception as e:
        return error_response(
            message="Failed to fetch customers", data=str(e), code=500
        )


@customer.patch("/{id}")
async def update_customer(
    id: str,
    update_data: dict,
    db: AsyncIOMotorDatabase = Depends(get_database),
    customer_service: CustomerService = Depends(get_service),
):
    """Update customer partially"""
    try:
        updated_customer = await customer_service.update_customer(id, update_data)
        return success_response(
            code=200, message="Customer updated successfully", data=updated_customer
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        return error_response(
            message="Failed to update customer", data=str(e), code=500
        )
