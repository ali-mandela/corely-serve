from motor.motor_asyncio import AsyncIOMotorDatabase
from fastapi import HTTPException, status
from app.utils.helpers import success_response, error_response, serialize_mongo_doc
from .helpers import (
    hash_password,
    verify_access_token,
    create_access_token,
    verify_password,
)


MODULE_MAP = {
    "users": "A",
    "stores": "B",
    "products": "C",
    "inventory": "D",
}

OPERATION_MAP = {
    "GET": "1",  # read
    "PUT": "2",  # update
    "PATCH": "2",
    "DELETE": "3",  # delete
    "POST": "4",  # create
}


class AuthService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.organizations = db.organizations
        self.users = db.users

    async def check_organization(self, slug: str):
        """Verify if organization exists and is active."""
        org = await self.organizations.find_one({"slug": slug})
        if not org or not org.get("is_active"):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invalid or inactive organization",
            )
        return org

    async def authenticate_user(self, user_data):
        """Authenticate user and issue JWT token."""
        org = await self.check_organization(user_data.slug)

        user = await self.users.find_one(
            {
                "$or": [
                    {"email": user_data.identifier},
                    {"phone": user_data.identifier},
                ],
                "organization_id": org["_id"],
            }
        )
        if not user:
            return error_response(message="User not found", code=404)

        if not verify_password(user_data.password, user.get("password", "")):
            return error_response(message="Invalid password", code=401)

        # --- Populate organization ---
        organization = await self.db.organizations.find_one(
            {"_id": user["organization_id"]}
        )
        if organization:
            organization["_id"] = str(organization["_id"])

        # --- Prepare user data (exclude password) ---
        user["_id"] = str(user["_id"])
        user["organization_id"] = str(user["organization_id"])
        user.pop("password", None)

        user = serialize_mongo_doc(user)
        organization = serialize_mongo_doc(organization)
        user["organization"] = organization

        # --- Create token ---
        token_payload = {
            "sub": str(user["_id"]),
            "role": user.get("role", "user"),
            "permissions": user.get("permissions", []),
            "org_slug": org.get("slug"),
        }

        token = create_access_token(data=token_payload)

        # --- Optionally update last login ---
        await self.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"last_login": org.get("slug")}},
        )

        # --- Success Response ---
        return success_response(
            message="Login successful",
            data={
                "access_token": token,
                "token_type": "bearer",
                "user": user,
            },
        )
