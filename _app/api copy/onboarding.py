from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app._core.database import get_database
from app._core.security import get_password_hash, create_access_token
from app._schemas.onboarding_schema import OnboardingRequest, OnboardingResponse
from app._schemas.organization_schema import OrganizationCreate
from app._schemas.user_schema import UserCreate
from app._models.user import UserRole
from app._services.organization_service import OrganizationService
from datetime import datetime, timezone

router = APIRouter()


@router.get("/status")
async def onboarding_status(db: AsyncIOMotorDatabase = Depends(get_database)):
    """Check if the system needs onboarding"""
    users_count = await db.users.count_documents({"role": "SUPER_ADMIN"})
    return {"needs_onboarding": users_count == 0, "super_admin_exists": users_count > 0}


@router.post("/setup", response_model=OnboardingResponse)
async def initial_setup(
    onboarding_data: OnboardingRequest, db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Initial system setup - creates super admin and organization"""

    # Check if super admin already exists
    existing_super_admin = await db.users.find_one(
        {"$or": [{"role": "SUPER_ADMIN"}, {"email": onboarding_data.admin_email}]}
    )
    if existing_super_admin:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="System already has a super admin. Onboarding not allowed.",
        )

    # Check if organization slug is unique
    existing_org = await db.organizations.find_one({"slug": onboarding_data.org_slug})
    if existing_org:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization slug already exists",
        )

    # Create organization
    org_data = OrganizationCreate(
        name=onboarding_data.org_name,
        slug=onboarding_data.org_slug,
        description=onboarding_data.org_description,
        email=onboarding_data.org_email,
        phone=onboarding_data.org_phone,
        website=onboarding_data.org_website,
        plan="premium",  # Super admin gets premium plan
        address=onboarding_data.org_address,
        allowed_modules=onboarding_data.allowed_modules,
    )

    # Create organization directly (bypass authorization for onboarding)
    org_doc = {
        "name": org_data.name,
        "slug": org_data.slug,
        "description": org_data.description,
        "email": org_data.email,
        "phone": org_data.phone,
        "website": org_data.website,
        "plan": org_data.plan,
        "address": org_data.address.dict() if org_data.address else None,
        "allowed_modules": org_data.allowed_modules,
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }

    org_result = await db.organizations.insert_one(org_doc)
    organization_id = str(org_result.inserted_id)

    # Create super admin user
    user_data = UserCreate(
        username=onboarding_data.admin_username,
        email=onboarding_data.admin_email,
        phone=onboarding_data.admin_phone,
        password=onboarding_data.admin_password,
        full_name=onboarding_data.admin_full_name,
        role=UserRole.SUPER_ADMIN,
        organization_id=organization_id,
        permissions=["*"],  # Super admin has all permissions
        is_active=True,
    )

    # Hash password and create user
    hashed_password = get_password_hash(user_data.password)
    user_doc = {
        "username": user_data.username,
        "email": user_data.email,
        "phone": user_data.phone,
        "hashed_password": hashed_password,
        "full_name": user_data.full_name,
        "role": user_data.role.value,
        "organization_id": user_data.organization_id,
        "permissions": user_data.permissions,
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }

    result = await db.users.insert_one(user_doc)
    user_id = str(result.inserted_id)

    # Generate access token for immediate login
    token_data = {
        "sub": user_id,
        "username": user_data.username,
        "role": user_data.role.value,
        "organization_id": user_data.organization_id,
    }
    access_token = create_access_token(token_data)

    return OnboardingResponse(
        message="System successfully initialized with super admin and organization",
        admin_user_id=user_id,
        organization_id=organization_id,
        access_token=access_token,
    )
