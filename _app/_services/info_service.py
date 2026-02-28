import secrets
import string
from datetime import datetime
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

from app._models.info import InfoModel as Info, AppAdminSecrets
from app._core.database import get_database
from app.utils.exceptions import DuplicateError, NotFoundError
from app.utils.helpers import stringify_object_id

from app._core.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    verify_token,
)

security = HTTPBearer()


class InfoService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.organisation_collection = db.organizations
        self.user_collection = db.users

    def verify_app_admin_secrets(self, admin_data: AppAdminSecrets) -> any:
        """Verify the provided admin secrets"""
        # For demo purposes, we use hardcoded secrets.
        expected_user_code = "securecorely"
        expected_org_id = "corely"
        exprected_temp_password = "corely@secure"
        if (
            admin_data.user_code == expected_user_code
            and admin_data.organization_id == expected_org_id
            and admin_data.temp_password == exprected_temp_password
        ):
            access_roken = create_access_token(
                subject={"role": "app_admin", "org_id": admin_data.organization_id}
            )
            return access_roken
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin secrets",
        )

    def _generate_random_password(self, length: int = 12) -> str:
        """Generate a secure random password"""
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return "".join(secrets.choice(alphabet) for _ in range(length))

    async def create_org_with_admin(self, info_data: Info) -> dict:
        """Create a new organisation and auto-generate super admin"""
        existing_org = await self.organisation_collection.find_one(
            {"name": info_data.name}
        )
        if existing_org:
            raise DuplicateError("Organisation name must be unique")

        new_org = {
            "name": info_data.name,
            "phone": info_data.phone,
            "email": info_data.email,
            "address": info_data.address.dict() if info_data.address else None,
            "is_active": (
                info_data.is_active if info_data.is_active is not None else True
            ),
            "created_at": datetime.utcnow(),
            "modules_enabled": [],
        }
        result = await self.organisation_collection.insert_one(new_org)
        org_id = result.inserted_id

        # ✅ Auto-generate admin user
        admin_username = f"{info_data.name.lower()}_admin"
        admin_email = info_data.email
        plain_password = self._generate_random_password()
        password_hash = get_password_hash(plain_password)

        admin_doc = {
            "username": admin_username,
            "email": admin_email,
            "password_hash": password_hash,
            "full_name": f"{info_data.name} Admin",
            "role": "admin",
            "organization_id": org_id,
            "store_ids": [],
            "permissions": ["*"],
            "is_active": True,
            "created_at": datetime.utcnow(),
            "last_login": None,
        }
        await self.user_collection.insert_one(admin_doc)

        # ✅ Return org info + admin credentials (password shown once!)
        created_org = await self.organisation_collection.find_one({"_id": org_id})
        return {
            "organisation": self._serialize_org(created_org),
            "admin": {
                "username": admin_username,
                "email": admin_email,
                "role": "admin",
                "password": plain_password,  # ⚠️ Only return once, don’t store plain
            },
        }

    async def get_org_by_id(self, org_id: str) -> dict:
        """Fetch organisation by id"""
        org = await self.organisation_collection.find_one({"_id": ObjectId(org_id)})
        if not org:
            raise NotFoundError("Organisation not found")
        return self._serialize_org(org)

    async def get_current_organisation(self, token: str) -> dict:
        """Get organisation based on token (payload contains org_id)"""
        payload = verify_token(token)
        org_id = payload.get("org_id")
        if not org_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: no org_id",
            )
        return await self.get_org_by_id(org_id)

    def _serialize_org(self, org: dict) -> dict:
        """Helper to serialize MongoDB doc"""
        return {
            "id": stringify_object_id(org["_id"]),
            "name": org["name"],
            "phone": org.get("phone"),
            "email": org.get("email"),
            "address": org.get("address"),
            "is_active": org.get("is_active", True),
            "modules_enabled": org.get("modules_enabled", []),
            "created_at": org.get("created_at"),
        }


# Dependencies
async def get_info_service(
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> InfoService:
    return InfoService(db)


async def get_current_organisation(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    info_service: InfoService = Depends(get_info_service),
) -> dict:
    """Dependency to get current org from JWT token"""
    return await info_service.get_current_organisation(credentials.credentials)
