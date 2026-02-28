from motor.motor_asyncio import AsyncIOMotorDatabase
from app._models.base import AdminInfo, AdminResponse, AdminLogin
from app.utils.exceptions import AuthenticationError, NotFoundError, DuplicateError
from datetime import datetime
from app._core.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    verify_token,
)
from app.utils.helpers import serialize_document, success_response, error_response
from fastapi import Depends
from app._core.database import get_database


class BaseService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db

    async def register_admin(self, admin_info: AdminInfo):
        """Register a new admin user"""
        existin_admin = await self.db.admins.find_one(
            {
                "$or": [
                    {"admin_email": admin_info.admin_email},
                    {"site_code": admin_info.site_code},
                ]
            }
        )

        if existin_admin:
            raise DuplicateError(
                "An admin with this email or site code already exists."
            )

        admin_doc = {
            **admin_info.dict(),
            "admin_password": get_password_hash(admin_info.admin_password),
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
        }
        result = await self.db.admins.insert_one(admin_doc)
        created_admin = serialize_document(
            await self.db.admins.find_one({"_id": result.inserted_id})
        )
        created_admin.pop("admin_password")
        return created_admin

    async def authenticate_admin(self, admin_info: AdminLogin) -> dict:
        """Authenticate admin by site code and password"""
        admin_doc = await self.db.admins.find_one(
            {
                "$or": [
                    {"site_code": admin_info.site_code},
                    {"admin_email": admin_info.email},
                ]
            }
        )
        if not admin_doc:
            raise AuthenticationError("Invalid site code or password")

        if not verify_password(admin_info.password, admin_doc["admin_password"]):
            raise AuthenticationError("Invalid site code or password")

        admin_doc_serialized = serialize_document(admin_doc)
        admin_doc_serialized.pop("admin_password", None)

        payload = {
            "admin_id": str(admin_doc_serialized["_id"]),
            "site_code": admin_doc_serialized["site_code"],
            "admin_email": admin_doc_serialized["admin_email"],
            "admin_role": admin_doc_serialized["admin_role"],
        }
        access_token = create_access_token(subject=payload)

        return {**payload, "token": access_token, "token_type": "bearer"}


async def get_base_service(
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> BaseService:
    return BaseService(db)
