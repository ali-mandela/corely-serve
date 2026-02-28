import secrets
import string
from datetime import datetime
from typing import List, Optional, Dict, Any
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo.errors import DuplicateKeyError
from app._core.security import verify_token, get_password_hash
from app._core.database import get_database


from app._models.organization import Organization, OrganizationSettings, OrganizationInfo
from app._models.user import User, UserRole
from app._schemas.organization_schema import (
    OrganizationCreate,
    OrganizationUpdate,
    OrganizationSettingsUpdate,
    OrganizationStats,
)
from app.utils.exceptions import ConflictError, NotFoundError, ValidationError

from functools import wraps
from typing import Callable, Any
from fastapi import HTTPException, status

from jose import JWTError, jwt


class OrganizationService:
    def __init__(self, database: AsyncIOMotorDatabase):
        self.db = database
        self.collection = database.organizations
        self.users_collection = database.users
        self.admins_collection = database.admins
        self.organsation_info_collection = database.organization_info

    def verify_app_admin(self, authorization_header: str) -> bool:
        """Verify if the authorization header contains a valid app_admin token"""
        if not authorization_header or not authorization_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid authorization header",
            )

        token = authorization_header.replace("Bearer ", "")
        payload = verify_token(token)

        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
            )

        user_role = payload.get("admin_role")
        if user_role != "APP_ADMIN":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: app_admin role required",
            )

        return payload.get("admin_id"), payload.get("site_code")

    def _generate_random_password(self, length: int = 12) -> str:
        """Generate a secure random password"""
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return "".join(secrets.choice(alphabet) for _ in range(length))

    async def create_organization(
        self, org_data: OrganizationCreate, authorization_header: str
    ):
        # Verify app_admin role
        admin_id, site_code = self.verify_app_admin(authorization_header)

        if not admin_id or not site_code:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: app_admin role required",
            )

        # Check if slug is unique
        existing_org = await self.collection.find_one({"slug": org_data.slug})
        if existing_org:
            raise ConflictError("Organization key already exists")

        # Check if email is unique
        existing_org = await self.collection.find_one({"email": org_data.email})
        if existing_org:
            raise ConflictError("Organization email already exists")

        # Generate admin credentials
        admin_username = f"{org_data.slug}_admin"
        admin_email = f"admin@{org_data.slug}.com"
        plain_password = self._generate_random_password()
        password_hash = get_password_hash(plain_password)

        print(site_code, str(ObjectId()) if not admin_id else admin_id)

        # Ensure admin_id is a valid ObjectId string
        if admin_id and ObjectId.is_valid(admin_id):
            created_by_id = admin_id
        else:
            created_by_id = str(ObjectId())

        # Ensure site_code is within length limits (max 20 chars)
        truncated_site_code = site_code[:20] if site_code else "DEFAULT"

        organization_data = dict(
            **org_data.model_dump(),
            created_by=created_by_id,
            site_code=truncated_site_code,
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )

        try:
            result = await self.collection.insert_one(organization_data)
            organization_data["_id"] = result.inserted_id

            # Create admin user for this organization
            admin_doc = {
                "username": admin_username,
                "email": admin_email,
                "password_hash": password_hash,
                "full_name": f"{org_data.name} Super Admin",
                "role": UserRole.SUPER_ADMIN.value,
                "organization_id": result.inserted_id,
                "store_ids": [],
                "permissions": ["*"],
                "is_active": True,
                "created_at": datetime.now(),
                "updated_at": datetime.now(),
                "last_login": None,
            }
            await self.users_collection.insert_one(admin_doc)

            # Store admin credentials for response
            organization_data["admin_credentials"] = {
                "username": admin_username,
                "email": admin_email,
                "password": plain_password,
            }

            # Convert datetime objects to strings for JSON serialization
            organization_data["_id"] = str(organization_data["_id"])
            organization_data["created_at"] = organization_data["created_at"].isoformat()
            organization_data["updated_at"] = organization_data["updated_at"].isoformat()
            organization_data["created_by"] = str(organization_data["created_by"])

            return organization_data
        except DuplicateKeyError:
            raise ConflictError("Organization with this slug or email already exists")

    # async def create_organization(
    #     self, org_data: OrganizationCreate, owner_id: str
    # ) -> Organization:
    #     # Check if slug is unique
    #     existing_org = await self.collection.find_one({"slug": org_data.slug})
    #     if existing_org:
    #         raise ConflictError("Organization slug already exists")

    #     # Check if email is unique
    #     existing_org = await self.collection.find_one({"email": org_data.email})
    #     if existing_org:
    #         raise ConflictError("Organization email already exists")

    #     organization = Organization(
    #         **org_data.model_dump(),
    #         owner_id=ObjectId(owner_id),
    #         admin_ids=[ObjectId(owner_id)]
    #     )

    #     try:
    #         result = await self.collection.insert_one(
    #             organization.model_dump(by_alias=True, exclude={"id"})
    #         )
    #         organization.id = result.inserted_id

    #         # Update the owner's role and organization
    #         await self.users_collection.update_one(
    #             {"_id": ObjectId(owner_id)},
    #             {
    #                 "$set": {
    #                     "organization_id": result.inserted_id,
    #                     "role": UserRole.ORG_OWNER.value,
    #                     "updated_at": datetime.utcnow()
    #                 }
    #             }
    #         )

    #         return organization
    #     except DuplicateKeyError:
    #         raise ConflictError("Organization with this slug or email already exists")

    # async def get_organization_by_id(self, org_id: str) -> Optional[Organization]:
    #     org_data = await self.collection.find_one({"_id": ObjectId(org_id)})
    #     if org_data:
    #         return Organization(**org_data)
    #     return None
