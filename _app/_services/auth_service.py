from datetime import datetime, timedelta
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

from app._core.database import get_database
from app._core.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    verify_token,
)
from app._core.config import settings
from app._models.user import User
from app._schemas.user_schema import (
    UserCreate,
    UserCreateFromInvitation,
    UserLogin,
    Token,
    UserResponse,
)
from app.utils.exceptions import AuthenticationError, NotFoundError, DuplicateError
from app.utils.helpers import serialize_datetime, parse_object_id, stringify_object_id

security = HTTPBearer()


class AuthService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.users_collection = db.users
        self.organizations_collection = db.organizations

    async def create_user(
        self, user_data: UserCreate, organization_id: str = None
    ) -> UserResponse:
        """Create a new user with required organization"""
        # Use provided organization_id or get from user_data
        org_id = organization_id or getattr(user_data, "organization_id", None)

        if not org_id:
            raise ValueError("Organization ID is required")

        # Check if organization exists
        org_doc = await self.organizations_collection.find_one(
            {"_id": ObjectId(org_id)}
        )
        if not org_doc:
            raise NotFoundError("Organization not found")

        # Check if username already exists in the same organization
        existing_user = await self.users_collection.find_one(
            {
                "$and": [
                    {"username": user_data.username},
                    {"organization_id": ObjectId(org_id)},
                ]
            }
        )
        if existing_user:
            raise DuplicateError("Username already exists in this organization")

        # Check if email already exists globally
        existing_email = await self.users_collection.find_one(
            {"email": user_data.email}
        )
        if existing_email:
            raise DuplicateError("Email already exists")

        # Hash the password
        password_hash = get_password_hash(user_data.password)

        # Create user document
        user_doc = {
            "username": user_data.username,
            "email": user_data.email,
            "phone": getattr(user_data, "phone", None),
            "password_hash": password_hash,
            "full_name": getattr(user_data, "full_name", None),
            "organization_id": ObjectId(org_id),
            "role": getattr(user_data, "role", "employee"),
            "store_ids": [
                ObjectId(store_id) for store_id in getattr(user_data, "store_ids", [])
            ],
            "default_store_id": (
                ObjectId(getattr(user_data, "default_store_id"))
                if getattr(user_data, "default_store_id", None)
                else None
            ),
            "permissions": getattr(user_data, "permissions", []),
            "custom_permissions": getattr(user_data, "custom_permissions", []),
            "avatar_url": getattr(user_data, "avatar_url", None),
            "timezone": getattr(user_data, "timezone", "UTC"),
            "language": getattr(user_data, "language", "en"),
            "is_active": True,
            "is_verified": False,
            "email_verified": False,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "last_login": None,
        }

        result = await self.users_collection.insert_one(user_doc)

        # Get the created user
        created_user = await self.users_collection.find_one({"_id": result.inserted_id})
        return self._serialize_user(created_user, org_doc)

    async def create_user_from_invitation(
        self, user_data: UserCreateFromInvitation, invitation_data: dict
    ) -> UserResponse:
        """Create user from invitation"""
        # Validate org_id from invitation
        if not invitation_data.get("org_id"):
            raise ValueError("Organisation ID is required in invitation")

        # Check if organization exists
        org_doc = await self.organizations_collection.find_one(
            {"_id": ObjectId(invitation_data["org_id"])}
        )
        if not org_doc:
            raise NotFoundError("Organization not found")

        # Check if username already exists
        existing_user = await self.users_collection.find_one(
            {"username": user_data.username}
        )
        if existing_user:
            raise DuplicateError("Username already exists")

        # Hash the password
        password_hash = get_password_hash(user_data.password)

        # Create user document from invitation data
        user_doc = {
            "username": user_data.username,
            "email": invitation_data["email"],
            "phone": invitation_data.get("phone"),
            "password_hash": password_hash,
            "full_name": user_data.full_name,
            "role": invitation_data["role"],
            "organization_id": ObjectId(
                invitation_data["org_id"]
            ),  # Required from invitation
            "store_ids": [
                ObjectId(store_id) for store_id in invitation_data.get("store_ids", [])
            ],
            "permissions": invitation_data.get("permissions", []),
            "is_active": True,
            "created_at": datetime.utcnow(),
            "last_login": None,
        }

        result = await self.users_collection.insert_one(user_doc)

        # Get the created user
        created_user = await self.users_collection.find_one({"_id": result.inserted_id})
        return self._serialize_user(created_user, org_doc)

    async def authenticate_user(self, login_data: UserLogin) -> Token:
        """Authenticate user and return JWT token"""

        # Try matching username, email, or phone
        user_doc = await self.users_collection.find_one(
            {
                "$or": [
                    {"username": login_data.identifier},
                    {"email": login_data.identifier},
                    {"phone": login_data.identifier},
                ],
                "is_active": True,
            }
        )
        if not user_doc or not verify_password(
            login_data.password,
            user_doc.get("hashed_password") or user_doc.get("password_hash"),
        ):
            raise AuthenticationError("Invalid credentials")

        # organization_id is required, so this should always exist
        if not user_doc.get("organization_id"):
            raise AuthenticationError("User has no organization assigned")

        org_doc = await self.organizations_collection.find_one(
            {"_id": ObjectId(user_doc["organization_id"])}
        )
        if not org_doc:
            raise AuthenticationError("User organization not found")

        # Update last login
        await self.users_collection.update_one(
            {"_id": user_doc["_id"]}, {"$set": {"last_login": datetime.utcnow()}}
        )

        # Create access token with user_id, role, organization_id
        payload = {
            "sub": str(user_doc["_id"]),
            "role": user_doc["role"],
            "organization_id": str(user_doc["organization_id"]),
        }
        access_token = create_access_token(subject=payload)

        return Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.access_token_expire_minutes * 60,
            user=self._serialize_user(user_doc, org_doc),
        )

    async def get_current_user(self, token: str) -> UserResponse:
        """Get current user from JWT token"""
        payload = verify_token(token)

        if not payload:
            raise AuthenticationError("Invalid token")
 
        # Check if payload is a dict or the old string format
        if isinstance(payload, dict):
            user_id = payload.get("sub")
            role = payload.get("role")
            organization_id = payload.get("organization_id")
        else:
            # Old format - payload is just the user_id string
            user_id = payload
            role = None
            organization_id = None

        if not user_id:
            raise AuthenticationError("Invalid token")

        try:
            user_doc = await self.users_collection.find_one(
                {"_id": ObjectId(user_id), "is_active": True}
            )

            if not user_doc:
                raise AuthenticationError("User not found")

        except Exception as e:
            print(f"Database error details: {e}")
            raise AuthenticationError("Database error")

        # ADD THE MISSING PART - organization check and user serialization
        if not user_doc.get("organization_id"):
            raise AuthenticationError("User has no organization assigned")

        org_doc = await self.organizations_collection.find_one(
            {"_id": ObjectId(user_doc["organization_id"])}
        )
        if not org_doc:
            raise AuthenticationError("User organization not found")

        return self._serialize_user(user_doc, org_doc)  # THIS WAS MISSING!

    async def get_user_by_id(self, user_id: str) -> Optional[UserResponse]:
        """Get user by ID"""
        try:
            user_doc = await self.users_collection.find_one({"_id": ObjectId(user_id)})
            if not user_doc:
                return None

            # organization_id is required
            if not user_doc.get("organization_id"):
                return None

            org_doc = await self.organizations_collection.find_one(
                {"_id": user_doc["organization_id"]}
            )
            if not org_doc:
                return None

            return self._serialize_user(user_doc, org_doc)
        except Exception:
            return None

    def _serialize_user(self, user_doc: dict, org_doc: dict) -> UserResponse:
        """Convert user document to UserResponse"""
        return UserResponse(
            id=stringify_object_id(user_doc["_id"]),
            username=user_doc["username"],
            email=user_doc["email"],
            phone=user_doc.get("phone"),
            full_name=user_doc.get("full_name"),
            role=user_doc["role"],
            organization_id=stringify_object_id(user_doc["organization_id"]),
            store_ids=[
                stringify_object_id(store_id)
                for store_id in user_doc.get("store_ids", [])
            ],
            default_store_id=(
                stringify_object_id(user_doc.get("default_store_id"))
                if user_doc.get("default_store_id")
                else None
            ),
            permissions=user_doc.get("permissions", []),
            custom_permissions=user_doc.get("custom_permissions", []),
            avatar_url=user_doc.get("avatar_url"),
            timezone=user_doc.get("timezone", "UTC"),
            language=user_doc.get("language", "en"),
            is_active=user_doc["is_active"],
            is_verified=user_doc.get("is_verified", False),
            email_verified=user_doc.get("email_verified", False),
            created_at=serialize_datetime(user_doc["created_at"]),
            updated_at=serialize_datetime(user_doc.get("updated_at")),
            last_login=serialize_datetime(user_doc.get("last_login")),
            organization={
                "id": stringify_object_id(org_doc["_id"]),
                "name": org_doc["name"],
                "slug": org_doc.get("slug"),
                "is_active": org_doc.get("is_active", True),
                "plan": org_doc.get("plan", "basic"),
            },
        )


async def get_auth_service(
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> AuthService:
    return AuthService(db)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    auth_service: AuthService = Depends(get_auth_service),
) -> UserResponse:
    """Dependency to get current authenticated user"""
    return await auth_service.get_current_user(credentials.credentials)
