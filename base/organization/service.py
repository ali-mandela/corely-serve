"""Organization service — create orgs + seed tenant collections."""

import secrets
import string
from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase
from fastapi import HTTPException, status

from base.tenant import get_tenant_collection, get_global_collection
from base.auth.helpers import hash_password
from base.utils import serialize_mongo_doc
from .schemas import OrgSetupRequest


def _generate_password(length: int = 12) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%"
    return "".join(secrets.choice(alphabet) for _ in range(length))


class OrganizationService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.orgs = get_global_collection(db, "organizations")

    async def slug_available(self, slug: str) -> bool:
        existing = await self.orgs.find_one({"slug": slug})
        return existing is None

    async def setup_organization(self, data: OrgSetupRequest) -> dict:
        """
        Full org setup:
          1. Check slug/email uniqueness
          2. Create org document in global `organizations`
          3. Create super_admin user in `{slug}_users`
          4. Return credentials
        """
        # ── 1. Uniqueness check ──────────────────────────────────
        existing = await self.orgs.find_one(
            {"$or": [{"slug": data.slug}, {"email": data.email}]}
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Organization with this slug or email already exists",
            )

        now = datetime.now(timezone.utc)

        # ── 2. Create organization ───────────────────────────────
        org_doc = {
            "name": data.name,
            "slug": data.slug,
            "email": data.email,
            "phone": data.phone,
            "address": data.address.model_dump(),
            "website": data.website,
            "description": data.description,
            "modules_enabled": [m.value for m in data.modules_enabled],
            "is_active": True,
            "created_at": now,
            "updated_at": now,
        }
        org_result = await self.orgs.insert_one(org_doc)
        org_doc["_id"] = org_result.inserted_id

        # ── 3. Create super_admin in tenant collection ───────────
        temp_password = _generate_password()
        admin_doc = {
            "name": data.owner_name,
            "email": data.owner_email,
            "password": hash_password(temp_password),
            "role": "super_admin",
            "permissions": ["*:*"],
            "is_active": True,
            "created_at": now,
            "updated_at": now,
        }

        users_col = get_tenant_collection(self.db, data.slug, "users")
        user_result = await users_col.insert_one(admin_doc)

        # ── 4. Link owner to org ─────────────────────────────────
        await self.orgs.update_one(
            {"_id": org_doc["_id"]},
            {"$set": {"owner_id": user_result.inserted_id}},
        )

        return {
            "organization_id": str(org_doc["_id"]),
            "organization_name": data.name,
            "slug": data.slug,
            "admin_user_id": str(user_result.inserted_id),
            "admin_email": data.owner_email,
            "temporary_password": temp_password,
            "setup_completed": True,
            "created_at": now,
            "message": "Organization setup completed. Change the temporary password on first login.",
        }
