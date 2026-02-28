"""
Profile Routes — user self-service endpoints.

These endpoints operate on the CURRENTLY LOGGED-IN user (from JWT).
No user ID is needed in the URL — we use request.state.user.

Endpoints:
    GET    /me                  Get own profile
    PUT    /me                  Update own profile (name, phone, avatar)
    POST   /change-password     Change own password
"""

from fastapi import APIRouter, Depends, Request
from motor.motor_asyncio import AsyncIOMotorDatabase

from base.config import get_database
from base.utils import success_response
from .schemas import UpdateProfileRequest, ChangePasswordRequest
from .service import ProfileService

profile_router = APIRouter()


def _get_context(request: Request) -> tuple[str, str]:
    """Extract org_slug and user_id from JWT-decoded request state."""
    slug = getattr(request.state, "org_slug", None)
    user = getattr(request.state, "user", {})
    user_id = user.get("sub")
    if not slug or not user_id:
        raise ValueError("Authentication context not found")
    return slug, user_id


@profile_router.get("/me")
async def get_my_profile(
    request: Request,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get the current logged-in user's profile.
    Returns all user fields except the hashed password.
    No special permission required — any authenticated user can access.
    """
    slug, user_id = _get_context(request)
    svc = ProfileService(db, slug)
    profile = await svc.get_profile(user_id)
    return success_response(data=profile)


@profile_router.put("/me")
async def update_my_profile(
    request: Request,
    body: UpdateProfileRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Update the current user's profile.

    Allowed fields: name, phone, avatar_url.
    Cannot change email, role, or permissions through this endpoint
    (those require admin-level access via /api/v1/users).
    """
    slug, user_id = _get_context(request)
    svc = ProfileService(db, slug)
    profile = await svc.update_profile(user_id, body.model_dump(exclude_unset=True))
    return success_response(data=profile, message="Profile updated")


@profile_router.post("/change-password")
async def change_password(
    request: Request,
    body: ChangePasswordRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Change the current user's password.

    Requirements:
        - Must provide the correct current password
        - New password must be at least 8 characters
        - Must contain at least 1 uppercase, 1 lowercase, 1 digit
        - Cannot reuse the current password

    On success, sets must_change_password=False (used for first-login flows).
    """
    slug, user_id = _get_context(request)
    svc = ProfileService(db, slug)
    result = await svc.change_password(user_id, body.current_password, body.new_password)
    return success_response(data=result, message="Password changed successfully")
