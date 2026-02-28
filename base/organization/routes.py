from fastapi import APIRouter, Depends, Request, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from base.config import settings, get_database
from base.utils import success_response
from .schemas import OrgSetupRequest, OrgSetupResponse
from .service import OrganizationService

org_router = APIRouter()


def _require_app_admin(request: Request):
    """Guard: only platform admins with the correct app-key can set up orgs."""
    role = request.headers.get("role")
    app_key = request.headers.get("app-key")

    if role != "system_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )
    if app_key != settings.app_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid app-key",
        )
    return True


@org_router.post("/set-up", response_model=OrgSetupResponse)
async def setup_organization(
    body: OrgSetupRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
    _: bool = Depends(_require_app_admin),
):
    """Set up a new organization with a super-admin user."""
    svc = OrganizationService(db)
    result = await svc.setup_organization(body)
    return result


@org_router.get("/check-slug/{slug}")
async def check_slug(
    slug: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Check whether an organization slug is available."""
    svc = OrganizationService(db)
    available = await svc.slug_available(slug)
    return {
        "slug": slug,
        "available": available,
        "message": "Slug is available" if available else "Slug is taken",
    }
