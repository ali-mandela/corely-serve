"""User service — CRUD on tenant-scoped user collection."""

from datetime import datetime, timezone
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase
from fastapi import HTTPException, status
from bson import ObjectId

from base.tenant import get_tenant_collection
from base.auth.helpers import hash_password
from base.rbac.roles import get_role_permissions
from base.utils import serialize_mongo_doc


class UserService:
    def __init__(self, db: AsyncIOMotorDatabase, org_slug: str):
        self.db = db
        self.org_slug = org_slug
        self.users = get_tenant_collection(db, org_slug, "users")

    async def create_user(self, data: dict, created_by: str | None = None) -> dict:
        """Create a new user. Hashes password, resolves permissions from role, checks email uniqueness."""
        # Check for duplicate email
        existing = await self.users.find_one({"email": data["email"]})
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this email already exists",
            )

        now = datetime.now(timezone.utc)
        role = data.get("role", "employee")

        user_doc = {
            **data,
            "password": hash_password(data["password"]),
            "permissions": data.get("permissions") or get_role_permissions(role),
            "is_active": data.get("is_active", True),
            "is_deleted": False,
            "created_by": created_by,
            "created_at": now,
            "updated_at": now,
        }

        result = await self.users.insert_one(user_doc)
        user_doc["_id"] = result.inserted_id

        safe = serialize_mongo_doc(user_doc)
        safe.pop("password", None)
        return safe

    async def get_user(self, user_id: str) -> dict:
        """Get a single user by ID (excludes password from response)."""
        if not ObjectId.is_valid(user_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid user ID",
            )
        user = await self.users.find_one(
            {"_id": ObjectId(user_id), "is_deleted": {"$ne": True}}
        )
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )
        safe = serialize_mongo_doc(user)
        safe.pop("password", None)
        return safe

    async def list_users(
        self,
        query: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        """List users with optional search by name, email, or username."""
        filters: dict = {"is_deleted": {"$ne": True}}
        if query:
            filters["$or"] = [
                {"name": {"$regex": query, "$options": "i"}},
                {"email": {"$regex": query, "$options": "i"}},
                {"username": {"$regex": query, "$options": "i"}},
            ]

        total = await self.users.count_documents(filters)
        cursor = self.users.find(filters).skip(offset).limit(limit).sort("created_at", -1)
        users = []
        async for u in cursor:
            safe = serialize_mongo_doc(u)
            safe.pop("password", None)
            users.append(safe)

        return users, total

    async def update_user(self, user_id: str, update_data: dict) -> dict:
        """Update user fields. Auto-resolves permissions if role changes."""
        if not ObjectId.is_valid(user_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid user ID",
            )

        # If role changed, auto-resolve permissions from new role
        if "role" in update_data and "permissions" not in update_data:
            update_data["permissions"] = get_role_permissions(update_data["role"])

        update_data["updated_at"] = datetime.now(timezone.utc)
        clean = {k: v for k, v in update_data.items() if v is not None}

        result = await self.users.find_one_and_update(
            {"_id": ObjectId(user_id), "is_deleted": {"$ne": True}},
            {"$set": clean},
            return_document=True,
        )
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )
        safe = serialize_mongo_doc(result)
        safe.pop("password", None)
        return safe

    async def delete_user(self, user_id: str) -> dict:
        """Soft-delete a user (sets is_deleted=True, preserves data)."""
        if not ObjectId.is_valid(user_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid user ID",
            )
        result = await self.users.update_one(
            {"_id": ObjectId(user_id), "is_deleted": {"$ne": True}},
            {"$set": {"is_deleted": True, "deleted_at": datetime.now(timezone.utc)}},
        )
        if result.modified_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found or already deleted",
            )
        return {"message": "User deleted successfully"}
