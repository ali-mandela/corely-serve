from motor.motor_asyncio import AsyncIOMotorDatabase
from datetime import datetime
from fastapi import HTTPException, status
from bson import ObjectId
from app.core.auth.helpers import hash_password
from typing import Optional


def serialize_user(user: dict) -> dict:
    """Convert MongoDB user document to a JSON-safe dict."""
    user_copy = user.copy()

    # Convert ObjectIds to strings
    for field in ["_id", "organization_id", "created_by"]:
        if field in user_copy and isinstance(user_copy[field], ObjectId):
            user_copy[field] = str(user_copy[field])

    # Convert datetimes to ISO strings
    for field in ["joining_date", "created_at", "updated_at"]:
        if field in user_copy and isinstance(user_copy[field], datetime):
            user_copy[field] = user_copy[field].isoformat()

    return user_copy


class UserService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.users = db.users
        self.organizations = db.organizations

    async def check_organization(self, slug: str):
        org = await self.organizations.find_one({"slug": slug})
        if not org or not org.get("is_active", False):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invalid or inactive organization",
            )
        return org

    async def create_user(self, employee, current_user: dict):
        org = await self.check_organization(current_user.get("org_slug", ""))

        employee_dict = employee.dict(exclude_unset=True)

        # Serialize special fields
        if employee_dict.get("profile_pic"):
            employee_dict["profile_pic"] = str(employee_dict["profile_pic"])

        if employee_dict.get("role"):
            employee_dict["role"] = str(employee_dict["role"])

        if employee_dict.get("password"):
            employee_dict["password"] = hash_password(employee_dict["password"])

        # Metadata
        employee_dict.update(
            {
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "organization_id": org["_id"],
                "created_by": current_user.get("sub"),
                "is_active": True,
                "is_deleted": False,
            }
        )

        result = await self.users.insert_one(employee_dict)
        employee_dict["_id"] = result.inserted_id

        return serialize_user(employee_dict)

    async def get_users(self, query: Optional[str], limit: int, offset: int):
        filters = {"is_deleted": False}
        if query:
            filters["$or"] = [
                {"name": {"$regex": query, "$options": "i"}},
                {"email": {"$regex": query, "$options": "i"}},
                {"username": {"$regex": query, "$options": "i"}},
            ]

        total = await self.users.count_documents(filters)
        cursor = self.users.find(filters).skip(offset).limit(limit)
        users = [serialize_user(u) async for u in cursor]

        return users, total
