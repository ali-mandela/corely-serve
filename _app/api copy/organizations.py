from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from motor.motor_asyncio import AsyncIOMotorDatabase

from app._core.database import get_database
from app._services.auth_service import get_current_user
from app._schemas.user_schema import UserResponse
from app._services.organization_service import OrganizationService
from app._schemas.organization_schema import (
    OrganizationCreate,
    OrganizationUpdate,
    OrganizationResponse,
    OrganizationSettingsUpdate,
    OrganizationStats,
    OrganizationInvite,
)
from app.utils.helpers import success_response, error_response

router = APIRouter()


def get_organization_service(
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> OrganizationService:
    return OrganizationService(db)


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_organization(
    organization_data: OrganizationCreate,
    request: Request = None,
    org_service: OrganizationService = Depends(get_organization_service),
):
    try:
        authorization_header = request.headers.get("authorization", "")
        organization = await org_service.create_organization(
            organization_data, authorization_header
        )
        return success_response(
            data=organization,
            message="Organization created successfully",
        )
    except Exception as e:
        return error_response(str(e))


@router.get("/", response_model=List[OrganizationResponse])
async def get_user_organizations(
    current_user: UserResponse = Depends(get_current_user),
    org_service: OrganizationService = Depends(get_organization_service),
):
    organizations = await org_service.get_user_organizations(str(current_user.id))
    return [
        OrganizationResponse(
            id=str(org.id),
            name=org.name,
            slug=org.slug,
            description=org.description,
            email=org.email,
            phone=org.phone,
            website=org.website,
            logo_url=org.logo_url,
            plan=org.plan,
            max_stores=org.max_stores,
            max_users=org.max_users,
            max_products=org.max_products,
            owner_id=str(org.owner_id),
            admin_ids=[str(admin_id) for admin_id in org.admin_ids],
            settings=(
                org.settings.model_dump()
                if hasattr(org.settings, "model_dump")
                else org.settings
            ),
            custom_settings=org.custom_settings,
            is_active=org.is_active,
            is_verified=org.is_verified,
            created_at=org.created_at,
            updated_at=org.updated_at,
        )
        for org in organizations
    ]


@router.get("/{organization_id}", response_model=OrganizationResponse)
async def get_organization(
    organization_id: str,
    current_user: UserResponse = Depends(get_current_user),
    org_service: OrganizationService = Depends(get_organization_service),
):
    organization = await org_service.get_organization_by_id(organization_id)
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Check if user has access to this organization
    if (
        current_user.role != "admin"
        and str(current_user.organization_id) != organization_id
    ):
        raise HTTPException(status_code=403, detail="Access denied")

    return OrganizationResponse(
        id=str(organization.id),
        name=organization.name,
        slug=organization.slug,
        description=organization.description,
        email=organization.email,
        phone=organization.phone,
        website=organization.website,
        logo_url=organization.logo_url,
        plan=organization.plan,
        max_stores=organization.max_stores,
        max_users=organization.max_users,
        max_products=organization.max_products,
        owner_id=str(organization.owner_id),
        admin_ids=[str(admin_id) for admin_id in organization.admin_ids],
        settings=(
            organization.settings.model_dump()
            if hasattr(organization.settings, "model_dump")
            else organization.settings
        ),
        custom_settings=organization.custom_settings,
        is_active=organization.is_active,
        is_verified=organization.is_verified,
        created_at=organization.created_at,
        updated_at=organization.updated_at,
    )


@router.put("/{organization_id}", response_model=OrganizationResponse)
async def update_organization(
    organization_id: str,
    update_data: OrganizationUpdate,
    current_user: UserResponse = Depends(get_current_user),
    org_service: OrganizationService = Depends(get_organization_service),
):
    try:
        organization = await org_service.update_organization(
            organization_id, update_data, str(current_user.id)
        )
        if not organization:
            raise HTTPException(status_code=404, detail="Organization not found")

        return OrganizationResponse(
            id=str(organization.id),
            name=organization.name,
            slug=organization.slug,
            description=organization.description,
            email=organization.email,
            phone=organization.phone,
            website=organization.website,
            logo_url=organization.logo_url,
            plan=organization.plan,
            max_stores=organization.max_stores,
            max_users=organization.max_users,
            max_products=organization.max_products,
            owner_id=str(organization.owner_id),
            admin_ids=[str(admin_id) for admin_id in organization.admin_ids],
            settings=(
                organization.settings.model_dump()
                if hasattr(organization.settings, "model_dump")
                else organization.settings
            ),
            custom_settings=organization.custom_settings,
            is_active=organization.is_active,
            is_verified=organization.is_verified,
            created_at=organization.created_at,
            updated_at=organization.updated_at,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/{organization_id}/settings", response_model=OrganizationResponse)
async def update_organization_settings(
    organization_id: str,
    settings_data: OrganizationSettingsUpdate,
    current_user: UserResponse = Depends(get_current_user),
    org_service: OrganizationService = Depends(get_organization_service),
):
    try:
        organization = await org_service.update_organization_settings(
            organization_id, settings_data, str(current_user.id)
        )
        if not organization:
            raise HTTPException(status_code=404, detail="Organization not found")

        return OrganizationResponse(
            id=str(organization.id),
            name=organization.name,
            slug=organization.slug,
            description=organization.description,
            email=organization.email,
            phone=organization.phone,
            website=organization.website,
            logo_url=organization.logo_url,
            plan=organization.plan,
            max_stores=organization.max_stores,
            max_users=organization.max_users,
            max_products=organization.max_products,
            owner_id=str(organization.owner_id),
            admin_ids=[str(admin_id) for admin_id in organization.admin_ids],
            settings=(
                organization.settings.model_dump()
                if hasattr(organization.settings, "model_dump")
                else organization.settings
            ),
            custom_settings=organization.custom_settings,
            is_active=organization.is_active,
            is_verified=organization.is_verified,
            created_at=organization.created_at,
            updated_at=organization.updated_at,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{organization_id}/stats", response_model=OrganizationStats)
async def get_organization_stats(
    organization_id: str,
    current_user: UserResponse = Depends(get_current_user),
    org_service: OrganizationService = Depends(get_organization_service),
):
    # Check if user has access to this organization
    if (
        current_user.role != "admin"
        and str(current_user.organization_id) != organization_id
    ):
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        stats = await org_service.get_organization_stats(organization_id)
        return stats
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{organization_id}/admins/{user_id}")
async def add_admin(
    organization_id: str,
    user_id: str,
    current_user: UserResponse = Depends(get_current_user),
    org_service: OrganizationService = Depends(get_organization_service),
):
    try:
        success = await org_service.add_admin(
            organization_id, user_id, str(current_user.id)
        )
        if not success:
            raise HTTPException(status_code=400, detail="Failed to add admin")
        return {"message": "Admin added successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{organization_id}/admins/{user_id}")
async def remove_admin(
    organization_id: str,
    user_id: str,
    current_user: UserResponse = Depends(get_current_user),
    org_service: OrganizationService = Depends(get_organization_service),
):
    try:
        success = await org_service.remove_admin(
            organization_id, user_id, str(current_user.id)
        )
        if not success:
            raise HTTPException(status_code=400, detail="Failed to remove admin")
        return {"message": "Admin removed successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{organization_id}/deactivate")
async def deactivate_organization(
    organization_id: str,
    current_user: UserResponse = Depends(get_current_user),
    org_service: OrganizationService = Depends(get_organization_service),
):
    try:
        success = await org_service.deactivate_organization(
            organization_id, str(current_user.id)
        )
        if not success:
            raise HTTPException(
                status_code=400, detail="Failed to deactivate organization"
            )
        return {"message": "Organization deactivated successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
