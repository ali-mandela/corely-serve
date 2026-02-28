"""
Profile Service — user self-service operations.

Allows authenticated users to:
    - View their own profile
    - Update their name, phone, avatar
    - Change their password (requires current password)
"""

from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase
from fastapi import HTTPException, status
from bson import ObjectId
from passlib.context import CryptContext

from base.tenant import get_tenant_collection
from base.utils import serialize_mongo_doc

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class ProfileService:
    def __init__(self, db: AsyncIOMotorDatabase, org_slug: str):
        self.db = db
        self.org_slug = org_slug
        self.users = get_tenant_collection(db, org_slug, "users")

    async def get_profile(self, user_id: str) -> dict:
        """Get the current user's profile (excludes password)."""
        if not ObjectId.is_valid(user_id):
            raise HTTPException(status_code=400, detail="Invalid user ID")

        user = await self.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        safe = serialize_mongo_doc(user)
        safe.pop("password", None)
        return safe

    async def update_profile(self, user_id: str, update_data: dict) -> dict:
        """
        Update the current user's own profile.
        Only allows updating: name, phone, avatar_url.
        Cannot change email, role, or permissions via this endpoint.
        """
        if not ObjectId.is_valid(user_id):
            raise HTTPException(status_code=400, detail="Invalid user ID")

        # Only allow safe fields
        allowed = {"name", "phone", "avatar_url"}
        clean = {k: v for k, v in update_data.items() if k in allowed and v is not None}

        if not clean:
            raise HTTPException(status_code=400, detail="No valid fields to update")

        clean["updated_at"] = datetime.now(timezone.utc)

        result = await self.users.find_one_and_update(
            {"_id": ObjectId(user_id)},
            {"$set": clean},
            return_document=True,
        )
        if not result:
            raise HTTPException(status_code=404, detail="User not found")

        safe = serialize_mongo_doc(result)
        safe.pop("password", None)
        return safe

    async def change_password(
        self, user_id: str, current_password: str, new_password: str
    ) -> dict:
        """
        Change the current user's password.
        Requires the current password for verification.
        """
        if not ObjectId.is_valid(user_id):
            raise HTTPException(status_code=400, detail="Invalid user ID")

        user = await self.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Verify current password
        if not pwd_context.verify(current_password, user.get("password", "")):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current password is incorrect",
            )

        # Prevent reusing the same password
        if pwd_context.verify(new_password, user.get("password", "")):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password cannot be the same as the current password",
            )

        # Hash and save new password
        hashed = pwd_context.hash(new_password)
        now = datetime.now(timezone.utc)

        await self.users.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$set": {
                    "password": hashed,
                    "password_changed_at": now,
                    "must_change_password": False,
                    "updated_at": now,
                }
            },
        )

        return {"message": "Password changed successfully"}
