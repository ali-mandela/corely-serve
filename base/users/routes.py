from fastapi import APIRouter, Depends, Request, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import Optional

from base.config import get_database
from base.utils import success_response, error_response
from base.rbac.decorators import require_permission
from .schemas import CreateUserRequest, UpdateUserRequest
from .service import UserService

users_router = APIRouter()


def _get_org_slug(request: Request) -> str:
    """Extract org_slug set by the AuthPermissionMiddleware."""
    slug = getattr(request.state, "org_slug", None)
    if not slug:
        raise ValueError("org_slug not found on request — is middleware active?")
    return slug


@users_router.post("/")
@require_permission("users:create")
async def create_user(
    request: Request,
    body: CreateUserRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    slug = _get_org_slug(request)
    current_user = request.state.user
    svc = UserService(db, slug)
    user = await svc.create_user(
        data=body.model_dump(),
        created_by=current_user.get("sub"),
    )
    return success_response(data=user, message="User created", code=201)


@users_router.get("/")
@require_permission("users:read")
async def list_users(
    request: Request,
    q: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    slug = _get_org_slug(request)
    svc = UserService(db, slug)
    users, total = await svc.list_users(query=q, limit=limit, offset=offset)
    return success_response(
        data={"users": users, "total": total, "limit": limit, "offset": offset}
    )


@users_router.get("/{user_id}")
@require_permission("users:read")
async def get_user(
    request: Request,
    user_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    slug = _get_org_slug(request)
    svc = UserService(db, slug)
    user = await svc.get_user(user_id)
    return success_response(data=user)


@users_router.put("/{user_id}")
@require_permission("users:update")
async def update_user(
    request: Request,
    user_id: str,
    body: UpdateUserRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    slug = _get_org_slug(request)
    svc = UserService(db, slug)
    user = await svc.update_user(user_id, body.model_dump(exclude_unset=True))
    return success_response(data=user, message="User updated")


@users_router.delete("/{user_id}")
@require_permission("users:delete")
async def delete_user(
    request: Request,
    user_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    slug = _get_org_slug(request)
    svc = UserService(db, slug)
    result = await svc.delete_user(user_id)
    return success_response(data=result, message="User deleted")
