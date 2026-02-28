"""Authentication service — login with tenant-scoped user lookup."""

from motor.motor_asyncio import AsyncIOMotorDatabase
from fastapi import HTTPException, status

from base.tenant import get_tenant_collection, get_global_collection
from base.rbac import get_role_permissions
from base.utils import serialize_mongo_doc
from .helpers import verify_password, create_access_token


class AuthService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db

    async def authenticate(self, identifier: str, password: str, slug: str) -> dict:
        """
        1. Verify the org exists in the global `organizations` collection.
        2. Look up the user in the tenant-scoped `{slug}_users` collection.
        3. Verify password and return JWT + user data.
        """
        # ── 1. Check organization ────────────────────────────────
        orgs = get_global_collection(self.db, "organizations")
        org = await orgs.find_one({"slug": slug})
        if not org or not org.get("is_active", False):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found or inactive",
            )

        # ── 2. Find user in tenant collection ────────────────────
        users = get_tenant_collection(self.db, slug, "users")
        user = await users.find_one(
            {
                "$or": [
                    {"email": identifier},
                    {"phone": identifier},
                    {"username": identifier},
                ]
            }
        )
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        if not user.get("is_active", True):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is deactivated",
            )

        # ── 3. Verify password ───────────────────────────────────
        if not verify_password(password, user.get("password", "")):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        # ── 4. Resolve permissions ───────────────────────────────
        role = user.get("role", "employee")
        permissions = user.get("permissions") or get_role_permissions(role)

        # ── 5. Build JWT ─────────────────────────────────────────
        token_payload = {
            "sub": str(user["_id"]),
            "org_slug": slug,
            "role": role,
            "permissions": permissions,
        }
        token = create_access_token(data=token_payload)

        # ── 6. Update last login ─────────────────────────────────
        from datetime import datetime, timezone

        await users.update_one(
            {"_id": user["_id"]},
            {"$set": {"last_login": datetime.now(timezone.utc)}},
        )

        # ── 7. Prepare response ──────────────────────────────────
        user_data = serialize_mongo_doc(user)
        user_data.pop("password", None)
        org_data = serialize_mongo_doc(org)
        user_data["organization"] = org_data

        return {
            "access_token": token,
            "token_type": "bearer",
            "user": user_data,
        }
