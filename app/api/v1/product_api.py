from fastapi import APIRouter, Depends, Request, Query, Body
from typing import Optional
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.core.config.database import get_database
from app.service.product_service import ProductService
from app.schema.producy_schema import ProductSchema
from app.utils.helpers import success_response, error_response, serialize_mongo_doc
from bson import ObjectId

product = APIRouter()


async def get_service(
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> ProductService:
    return ProductService(db)


@product.post("")
async def create_product(
    request: Request,
    product_data: ProductSchema,
    db: AsyncIOMotorDatabase = Depends(get_database),
    product_service: ProductService = Depends(get_service),
):
    c = request.state.user
    org = await db["organizations"].find_one({"slug": c.get("org_slug")})
    if org is None:
        error_response(message="Organization not found", code=404)
    else:
        c["organization_id"] = str(org["_id"])

    try:
        result = await product_service.create_product(product_data, c)
        return success_response(
            code=201, message="Product created successfully", data=result
        )
    except Exception as e:
        return error_response(
            message=f"Failed to create product", data=str(e), code=500
        )


@product.get("/{id}")
async def get_product(id: str, product_service: ProductService = Depends(get_service)):
    if not ObjectId.is_valid(id):
        return error_response(message="Invalid product ID", code=400)

    product = await product_service.get_product_by_id(ObjectId(id))

    if not product:
        return error_response(message="Product not found", code=404)

    return success_response(
        code=200, message="Product fetched successfully", data=product
    )


@product.get("")
async def list_products(
    category: Optional[str] = Query(None, description="Filter by category"),
    limit: int = Query(20, ge=1, le=100, description="Number of products per page"),
    skip: int = Query(0, ge=0, description="Number of products to skip"),
    search: Optional[str] = Query(None, description="Search by name or description"),
    product_service: ProductService = Depends(get_service),
):
    data = await product_service.list_products(
        category=category, search=search, limit=limit, skip=skip
    )
    return success_response(
        code=200, message="Products fetched successfully", data=data
    )


@product.delete("/{id}")
async def delete_product(
    id: str, product_service: ProductService = Depends(get_service)
):
    success = await product_service.delete_product(id)
    if success:
        return success_response(
            code=200, message="Product deleted successfully", data={"product_id": id}
        )
    return error_response(code=404, message="Product not found")


@product.patch("/{id}")
async def patch_product(
    id: str,
    update_data: dict = Body(..., description="Partial product data to update"),
    product_service: ProductService = Depends(get_service),
):
    updated_product = await product_service.update_product(id, update_data)
    if updated_product:
        return success_response(
            code=200, message="Product updated successfully", data=updated_product
        )
    return error_response(code=404, message="Product not found")
