# """This contains the open api's to setup an organisation"""

# from fastapi import APIRouter, Depends, HTTPException, Request, status
# from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# from pydantic import BaseModel, Field, EmailStr, field_validator
# from typing import Optional, List, Dict, Any
# from datetime import datetime
# from enum import Enum
# from bson import ObjectId
# import secrets
# import string
# import hashlib
# import re
# import traceback
# from app.core.config.corely_settings import CorelySettings
# from app.core.config.database import DatabaseManager

# # Initialize components
# base_api = APIRouter()
# security = HTTPBearer()
# settings = CorelySettings()
# db = DatabaseManager()


# # Enums
# class ModuleEnum(str, Enum):
#     EMPLOYEE_MANAGEMENT = "employee"
#     BILLING = "billing"
#     ANALYTICS = "analytics"
#     NOTIFICATIONS = "notifications"
#     REPORTING = "reporting"
#     STORES = "stores"
#     ALL = "*"


# class CountryEnum(str, Enum):
#     INDIA = "India"
#     USA = "United States"
#     UK = "United Kingdom"
#     CANADA = "Canada"


# # Models
# class AddressModel(BaseModel):
#     pin_code: str = Field(..., min_length=4, max_length=10, description="Postal code")
#     location: Optional[str] = Field(None, max_length=100, description="Area/Landmark")
#     street: str = Field(..., min_length=5, max_length=200, description="Street address")
#     district: str = Field(
#         ..., min_length=2, max_length=100, description="District/City"
#     )
#     state: str = Field(..., min_length=2, max_length=100, description="State/Province")
#     country: CountryEnum = Field(..., description="Country")


# class OrganizationSetupRequest(BaseModel):
#     name: str = Field(
#         ..., min_length=3, max_length=100, description="Organization name"
#     )
#     slug: str = Field(
#         ..., min_length=3, max_length=50, description="URL-friendly identifier"
#     )
#     email: EmailStr = Field(..., description="Primary organization email")
#     phone: str = Field(..., min_length=10, max_length=15, description="Contact phone")
#     address: AddressModel = Field(..., description="Organization address")
#     owner_email: EmailStr = Field(..., description="Super admin email")
#     owner_name: str = Field(
#         ..., min_length=2, max_length=100, description="Super admin name"
#     )
#     website: Optional[str] = Field(None, description="Organization website")
#     modules_enabled: List[ModuleEnum] = Field(
#         default=[ModuleEnum.EMPLOYEE_MANAGEMENT],
#         description="Initial modules to enable",
#     )
#     description: Optional[str] = Field(
#         None, max_length=500, description="Organization description"
#     )

#     @field_validator("slug")
#     @classmethod
#     def validate_slug(cls, v):
#         if not re.match(r"^[a-z0-9\-]+$", v):
#             raise ValueError(
#                 "Slug must contain only lowercase letters, numbers, and hyphens"
#             )
#         if v != v.lower():
#             raise ValueError("Slug must be lowercase")
#         return v

#     @field_validator("phone")
#     @classmethod
#     def validate_phone(cls, v):
#         cleaned = re.sub(r"[\s\-\(\)]", "", v)
#         if not cleaned.replace("+", "").isdigit():
#             raise ValueError("Invalid phone number format")
#         return v

#     @field_validator("website")
#     @classmethod
#     def validate_website(cls, v):
#         if v and not re.match(r"^https?:\/\/.+", v):
#             raise ValueError("Website must start with http:// or https://")
#         return v


# class OrganizationSetupResponse(BaseModel):
#     organization_id: str
#     organization_name: str
#     slug: str
#     admin_user_id: str
#     admin_email: str
#     temporary_password: str
#     setup_completed: bool
#     created_at: datetime
#     message: str


# # Authentication decorator
# def require_admin_role(required_role: str):
#     async def check_role(request: Request):
#         try:
#             user_role = request.headers.get("role")
#             app_key = request.headers.get("app-key")

#             if not user_role or user_role != required_role:
#                 raise HTTPException(
#                     status_code=status.HTTP_403_FORBIDDEN,
#                     detail="Insufficient permissions",
#                 )

#             if not app_key or app_key != settings.app_key:
#                 raise HTTPException(
#                     status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid app-key"
#                 )

#             return {"role": user_role, "app_key_valid": True, "authenticated": True}

#         except HTTPException:
#             raise
#         except Exception as e:
#             print(f"Authentication error: {e}")
#             raise HTTPException(
#                 status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#                 detail="Authentication failed",
#             )

#     return check_role


# # Utility functions
# def generate_random_password(length: int = 12) -> str:
#     """Generate a secure random password"""
#     alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
#     password = "".join(secrets.choice(alphabet) for _ in range(length))
#     return password


# def hash_password(password: str) -> str:
#     """Hash password using SHA-256"""
#     salt = secrets.token_hex(16)
#     password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
#     return f"{salt}:{password_hash}"


# async def check_organization_exists(slug: str, email: str) -> bool:
#     """Check if organization already exists"""
#     try:
#         # Check by slug
#         org_by_slug = await db.database["organizations"].find_one({"slug": slug})
#         if org_by_slug:
#             return True

#         # Check by email
#         org_by_email = await db.database["organizations"].find_one({"email": email})
#         if org_by_email:
#             return True

#         return False
#     except Exception as e:
#         print(f"Error checking organization existence: {e}")
#         return False


# async def create_super_admin_user(
#     org_id: ObjectId, owner_name: str, owner_email: str
# ) -> Dict[str, Any]:
#     """Create super admin user for the organization"""
#     try:
#         # Generate password
#         temp_password = generate_random_password()
#         hashed_password = hash_password(temp_password)

#         admin_user = {
#             # No need to specify _id, MongoDB will generate it automatically
#             "name": owner_name,
#             "email": owner_email,
#             "password": hashed_password,
#             "role": "super_admin",
#             "organization_id": org_id,  # Reference to organization's _id
#             "is_active": True,
#             "is_verified": False,
#             "permissions": [
#                 "manage_users",
#                 "manage_organization",
#                 "manage_billing",
#                 "manage_modules",
#                 "view_analytics",
#                 "system_admin",
#             ],
#             "created_at": datetime.utcnow(),
#             "updated_at": datetime.utcnow(),
#             "last_login": None,
#             "login_attempts": 0,
#             "account_locked": False,
#         }

#         # Insert into users collection
#         result = await db.database["users"].insert_one(admin_user)
#         if not result.inserted_id:
#             raise Exception("Failed to create admin user")

#         return {
#             "user_id": str(result.inserted_id),  # Convert ObjectId to string
#             "email": owner_email,
#             "temporary_password": temp_password,
#         }

#     except Exception as e:
#         print(f"Error creating super admin user: {e}")
#         raise Exception(f"Failed to create admin user: {str(e)}")


# async def create_organization(
#     org_data: OrganizationSetupRequest, admin_user_id: ObjectId
# ) -> Dict[str, Any]:
#     """Create organization record"""
#     try:
#         organization = {
#             # No need to specify _id, MongoDB will generate it automatically
#             "name": org_data.name,
#             "slug": org_data.slug,
#             "email": org_data.email,
#             "phone": org_data.phone,
#             "address": org_data.address.model_dump(),
#             "owner_id": admin_user_id,  # Reference to admin user's _id
#             "website": org_data.website,
#             "modules_enabled": [module.value for module in org_data.modules_enabled],
#             "description": org_data.description,
#             "is_active": True,
#             "subscription_tier": "basic",
#             "max_users": 10,
#             "current_users": 1,  # Super admin user
#             "settings": {
#                 "allow_user_registration": False,
#                 "require_email_verification": True,
#                 "session_timeout": 3600,
#                 "password_policy": {
#                     "min_length": 8,
#                     "require_special_chars": True,
#                     "require_numbers": True,
#                 },
#             },
#             "created_at": datetime.utcnow(),
#             "updated_at": datetime.utcnow(),
#         }

#         # Insert into organizations collection
#         result = await db.database["organizations"].insert_one(organization)
#         if not result.inserted_id:
#             logger(traceback.format_exc(), "logger", "text")
#             raise Exception("Failed to create organization")

#         # Add the _id to the organization dict for return
#         organization["_id"] = result.inserted_id

#         return {
#             "organization_id": str(result.inserted_id),  # Convert ObjectId to string
#             "organization": organization,
#         }

#     except Exception as e:
#         print(f"Error creating organization: {e}")
#         logger(traceback.format_exc(), "logger", "text")

#         raise Exception(f"Failed to create organization: {str(e)}")


# # API Endpoints
# @base_api.post("/set-up", response_model=OrganizationSetupResponse)
# async def setup_organization_endpoint(
#     org_data: OrganizationSetupRequest,
#     request: Request,
#     user: dict = Depends(require_admin_role("only_app_admin")),
# ):
#     """
#     Setup a new organization with super admin user.

#     This endpoint:
#     1. Validates organization data
#     2. Checks if organization already exists
#     3. Creates the organization record (gets MongoDB _id)
#     4. Creates a super admin user with reference to organization _id
#     5. Updates organization with admin user reference
#     6. Returns setup details including temporary password

#     **Note**: The temporary password should be changed on first login.
#     """
#     try:
#         # Check if organization already exists
#         org_exists = await check_organization_exists(org_data.slug, org_data.email)
#         if org_exists:
#             raise HTTPException(
#                 status_code=status.HTTP_409_CONFLICT,
#                 detail="Organization with this slug or email already exists",
#             )

#         # Step 1: Create organization first to get MongoDB _id
#         temp_org_info = await create_organization(
#             org_data, None
#         )  # No admin_user_id yet
#         org_id = ObjectId(temp_org_info["organization_id"])

#         # Step 2: Create super admin user with organization _id reference
#         admin_user_info = await create_super_admin_user(
#             org_id=org_id,
#             owner_name=org_data.owner_name,
#             owner_email=org_data.owner_email,
#         )
#         admin_user_id = ObjectId(admin_user_info["user_id"])

#         # Step 3: Update organization with admin user reference
#         await db.database["organizations"].update_one(
#             {"_id": org_id}, {"$set": {"owner_id": admin_user_id}}
#         )

#         # Return setup response
#         return OrganizationSetupResponse(
#             organization_id=temp_org_info["organization_id"],
#             organization_name=org_data.name,
#             slug=org_data.slug,
#             admin_user_id=admin_user_info["user_id"],
#             admin_email=admin_user_info["email"],
#             temporary_password=admin_user_info["temporary_password"],
#             setup_completed=True,
#             created_at=temp_org_info["organization"]["created_at"],
#             message="Organization setup completed successfully. Please change the temporary password on first login.",
#         )

#     except HTTPException:
#         raise
#     except Exception as e:
#         print(f"Organization setup error: {e}")
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=f"Organization setup failed: {str(e)}",
#         )


# @base_api.get("/health")
# async def health_check():
#     """Health check endpoint for organization setup service"""
#     return {
#         "status": "healthy",
#         "service": "Organization Setup API",
#         "timestamp": datetime.utcnow(),
#         "version": "1.0.0",
#     }


# @base_api.get("/check-slug/{slug}")
# async def check_slug_availability(slug: str):
#     """Check if organization slug is available"""
#     try:
#         exists = await db.database["organizations"].find_one({"slug": slug})
#         return {
#             "slug": slug,
#             "available": not bool(exists),
#             "message": "Slug is available" if not exists else "Slug is already taken",
#         }
#     except Exception as e:
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail="Error checking slug availability",
#         )


"""Organization Setup APIs using class-based DB dependency"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field, EmailStr, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
from bson import ObjectId
import secrets
import string
import hashlib
import re
import traceback

from app.core.config.corely_settings import CorelySettings
from app.core.config.database import DatabaseManager

# Initialize components
base_api = APIRouter()
security = HTTPBearer()
settings = CorelySettings()

# ------------------ Dependency Provider ------------------


async def get_db() -> DatabaseManager:
    db_manager = DatabaseManager()
    await db_manager.connect()  # make sure connection happens
    try:
        yield db_manager
    finally:
        db_manager.closeConnection()


# ------------------ Enums ------------------


class ModuleEnum(str, Enum):
    EMPLOYEE_MANAGEMENT = "employee"
    BILLING = "billing"
    ANALYTICS = "analytics"
    NOTIFICATIONS = "notifications"
    REPORTING = "reporting"
    STORES = "stores"
    ALL = "*"


class CountryEnum(str, Enum):
    INDIA = "India"
    USA = "United States"
    UK = "United Kingdom"
    CANADA = "Canada"


# ------------------ Models ------------------


class AddressModel(BaseModel):
    pin_code: str = Field(..., min_length=4, max_length=10, description="Postal code")
    location: Optional[str] = Field(None, max_length=100, description="Area/Landmark")
    street: str = Field(..., min_length=5, max_length=200, description="Street address")
    district: str = Field(
        ..., min_length=2, max_length=100, description="District/City"
    )
    state: str = Field(..., min_length=2, max_length=100, description="State/Province")
    country: CountryEnum = Field(..., description="Country")


class OrganizationSetupRequest(BaseModel):
    name: str = Field(
        ..., min_length=3, max_length=100, description="Organization name"
    )
    slug: str = Field(
        ..., min_length=3, max_length=50, description="URL-friendly identifier"
    )
    email: EmailStr = Field(..., description="Primary organization email")
    phone: str = Field(..., min_length=10, max_length=15, description="Contact phone")
    address: AddressModel = Field(..., description="Organization address")
    owner_email: EmailStr = Field(..., description="Super admin email")
    owner_name: str = Field(
        ..., min_length=2, max_length=100, description="Super admin name"
    )
    website: Optional[str] = Field(None, description="Organization website")
    modules_enabled: List[ModuleEnum] = Field(
        default=[ModuleEnum.EMPLOYEE_MANAGEMENT],
        description="Initial modules to enable",
    )
    description: Optional[str] = Field(
        None, max_length=500, description="Organization description"
    )

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, v):
        if not re.match(r"^[a-z0-9\-]+$", v):
            raise ValueError(
                "Slug must contain only lowercase letters, numbers, and hyphens"
            )
        if v != v.lower():
            raise ValueError("Slug must be lowercase")
        return v

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v):
        cleaned = re.sub(r"[\s\-\(\)]", "", v)
        if not cleaned.replace("+", "").isdigit():
            raise ValueError("Invalid phone number format")
        return v

    @field_validator("website")
    @classmethod
    def validate_website(cls, v):
        if v and not re.match(r"^https?:\/\/.+", v):
            raise ValueError("Website must start with http:// or https://")
        return v


class OrganizationSetupResponse(BaseModel):
    organization_id: str
    organization_name: str
    slug: str
    admin_user_id: str
    admin_email: str
    temporary_password: str
    setup_completed: bool
    created_at: datetime
    message: str


# ------------------ Authentication ------------------


def require_admin_role(required_role: str):
    async def check_role(request: Request):
        user_role = request.headers.get("role")
        app_key = request.headers.get("app-key")
        if not user_role or user_role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
            )
        if not app_key or app_key != settings.app_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid app-key"
            )
        return {"role": user_role, "app_key_valid": True, "authenticated": True}

    return check_role


# ------------------ Utilities ------------------


def generate_random_password(length: int = 12) -> str:
    alphabet = string.ascii_letters + string.digits + "!pass"
    return "".join(secrets.choice(alphabet) for _ in range(length))


from passlib.context import CryptContext

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)


# ------------------ DB Operations ------------------


async def check_organization_exists(
    slug: str, email: str, db: DatabaseManager = Depends(get_db)
) -> bool:
    org_by_slug = await db.database["organizations"].find_one({"slug": slug})
    org_by_email = await db.database["organizations"].find_one({"email": email})
    return bool(org_by_slug or org_by_email)


async def create_super_admin_user(
    org_id: ObjectId,
    owner_name: str,
    owner_email: str,
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    temp_password = generate_random_password()
    hashed_password = hash_password(temp_password)
    admin_user = {
        "name": owner_name,
        "email": owner_email,
        "password": hashed_password,
        "role": "super_admin",
        "organization_id": org_id,
        "is_active": True,
        "permissions": ["manage_users", "manage_organization", "system_admin"],
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    result = await db.database["users"].insert_one(admin_user)
    return {
        "user_id": str(result.inserted_id),
        "email": owner_email,
        "temporary_password": temp_password,
    }


async def create_organization(
    org_data: OrganizationSetupRequest,
    admin_user_id: ObjectId = None,
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    organization = {
        "name": org_data.name,
        "slug": org_data.slug,
        "email": org_data.email,
        "phone": org_data.phone,
        "address": org_data.address.model_dump(),
        "owner_id": admin_user_id,
        "modules_enabled": [m.value for m in org_data.modules_enabled],
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    result = await db.database["organizations"].insert_one(organization)
    organization["_id"] = result.inserted_id
    return {"organization_id": str(result.inserted_id), "organization": organization}


# ------------------ API Endpoints ------------------


@base_api.post("/set-up", response_model=OrganizationSetupResponse)
async def setup_organization_endpoint(
    org_data: OrganizationSetupRequest,
    request: Request,
    db: DatabaseManager = Depends(get_db),
    user: dict = Depends(require_admin_role("only_app_admin")),
):
    try:
        if await check_organization_exists(org_data.slug, org_data.email, db):
            raise HTTPException(status_code=409, detail="Organization already exists")

        temp_org_info = await create_organization(org_data, None, db)
        org_id = ObjectId(temp_org_info["organization_id"])

        admin_info = await create_super_admin_user(
            org_id, org_data.owner_name, org_data.owner_email, db
        )
        await db.database["organizations"].update_one(
            {"_id": org_id}, {"$set": {"owner_id": ObjectId(admin_info["user_id"])}}
        )

        return OrganizationSetupResponse(
            organization_id=temp_org_info["organization_id"],
            organization_name=org_data.name,
            slug=org_data.slug,
            admin_user_id=admin_info["user_id"],
            admin_email=admin_info["email"],
            temporary_password=admin_info["temporary_password"],
            setup_completed=True,
            created_at=temp_org_info["organization"]["created_at"],
            message="Organization setup completed successfully.",
        )
    except Exception as e:
        import traceback

        logger(traceback.format_exc(), "log", "text")


@base_api.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "Organization Setup API",
        "timestamp": datetime.utcnow(),
        "version": "1.0.0",
    }


@base_api.get("/check-slug/{slug}")
async def check_slug_availability(slug: str, db: DatabaseManager = Depends(get_db)):
    exists = await db.database["organizations"].find_one({"slug": slug})
    return {
        "slug": slug,
        "available": not bool(exists),
        "message": "Slug is available" if not exists else "Slug is taken",
    }


def logger(value, file_name="log", file_type="json"):
    import os
    from bson import json_util

    try:
        os.makedirs("log_files", exist_ok=True)
        if file_type == "json":
            with open(f"log_files/{file_name}.json", "w") as f:
                f.write(json_util.dumps(value, indent=4))
        else:
            with open(f"log_files/{file_name}.txt", "w") as f:
                f.write(str(value))
        print(f"Successfully wrote data to {file_name} file")

    except Exception as e:
        print(f"Failed to write to file: {e}")
