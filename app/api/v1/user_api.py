from fastapi import APIRouter, Depends, Request, HTTPException, Query, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import Optional

from app.core.config.database import get_database
from app.service.user_service import UserService
from app.schema.user_schema import Employee
from app.utils.helpers import success_response, error_response

users = APIRouter()

# Pagination defaults
DEFAULT_LIMIT = 20
MAX_LIMIT = 100


# Dependency injector for the service
async def get_service(db: AsyncIOMotorDatabase = Depends(get_database)) -> UserService:
    return UserService(db)


@users.post("")
async def create_user(
    request: Request,
    employee_data: Employee,
    user_service: UserService = Depends(get_service),
):
    """
    Create a new user (employee) under the authenticated user's organization.
    """
    if not getattr(request.state, "user", None):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
        )

    try:
        result = await user_service.create_user(employee_data, request.state.user)
        return success_response(message="User created successfully", data=result)
    except HTTPException as e:
        raise e
    except Exception as e:
        return error_response(f"Failed to create user: {str(e)}")


@users.get("", summary="Get list of users", tags=["Users"])
async def get_users(
    query: Optional[str] = Query(
        None, description="Search term for name, email or username"
    ),
    limit: int = Query(
        DEFAULT_LIMIT, ge=1, le=MAX_LIMIT, description="Number of users per page"
    ),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    user_service: UserService = Depends(get_service),
):
    """
    Retrieve users with optional search and pagination.
    """
    try:
        users_data, total = await user_service.get_users(
            query=query, limit=limit, offset=offset
        )
        return success_response(
            message="Users fetched successfully",
            data={
                "results": users_data,
                "pagination": {
                    "limit": limit,
                    "offset": offset,
                    "total": total,
                    "has_next": total > offset + limit,
                },
            },
        )
    except Exception as e:
        return error_response(f"Failed to fetch users: {str(e)}")
