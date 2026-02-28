from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

from app._core.database import get_database
from app._services.auth_service import AuthService, get_auth_service, get_current_user
from app._schemas.user_schema import (
    UserCreate, UserUpdate, UserResponse, UserListResponse
)
from app._models.user import UserRole
from app.utils.exceptions import NotFoundError, DuplicateError, ValidationError
from app.utils.helpers import calculate_pagination, serialize_datetime

router = APIRouter()


def require_user_management_permission(current_user: UserResponse = Depends(get_current_user)):
    """Dependency to ensure user can manage other users"""
    if current_user.role not in [UserRole.ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Permission denied: Cannot manage users"
        )
    return current_user


def require_manager_permission(current_user: UserResponse = Depends(get_current_user)):
    """Dependency to ensure user has manager+ permission"""
    if current_user.role not in [UserRole.ADMIN, UserRole.MANAGER]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Permission denied: Manager access required"
        )
    return current_user


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate,
    current_user: UserResponse = Depends(require_user_management_permission),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Create a new user (employee)"""
    try:
        # Use current user's organization
        return await auth_service.create_user(user_data, current_user.organization_id)
    except DuplicateError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/", response_model=UserListResponse)
async def list_users(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None),
    role: Optional[UserRole] = Query(None),
    store_id: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    current_user: UserResponse = Depends(require_manager_permission),
    auth_service: AuthService = Depends(get_auth_service),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """List users with pagination and filters"""
    skip = (page - 1) * per_page
    query = {"organization_id": ObjectId(current_user.organization_id)}
    
    # Apply filters
    if search:
        query["$or"] = [
            {"username": {"$regex": search, "$options": "i"}},
            {"full_name": {"$regex": search, "$options": "i"}},
            {"email": {"$regex": search, "$options": "i"}},
        ]
    
    if role:
        query["role"] = role.value
        
    if store_id:
        query["store_ids"] = ObjectId(store_id)
        
    if is_active is not None:
        query["is_active"] = is_active
    
    # Get total count
    total = await db.users.count_documents(query)
    
    # Get users
    users_cursor = db.users.find(query).sort("created_at", -1).skip(skip).limit(per_page)
    users = await users_cursor.to_list(length=per_page)
    
    # Get organization info for serialization
    org_doc = await db.organizations.find_one({"_id": ObjectId(current_user.organization_id)})
    
    # Serialize users
    serialized_users = []
    for user_doc in users:
        serialized_users.append(auth_service._serialize_user(user_doc, org_doc))
    
    return UserListResponse(
        users=serialized_users,
        **calculate_pagination(page, per_page, total)
    )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: UserResponse = Depends(require_manager_permission),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Get user by ID"""
    user = await auth_service.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    # Check if user belongs to same organization
    if user.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    return user


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    user_data: UserUpdate,
    current_user: UserResponse = Depends(require_user_management_permission),
    auth_service: AuthService = Depends(get_auth_service),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Update user"""
    try:
        # Check if user exists and belongs to same organization
        existing_user = await auth_service.get_user_by_id(user_id)
        if not existing_user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        if existing_user.organization_id != current_user.organization_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        # Prepare update data
        update_data = {k: v for k, v in user_data.dict().items() if v is not None}
        if not update_data:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No data provided for update")
        
        # Convert store IDs to ObjectIds if provided
        if "store_ids" in update_data:
            update_data["store_ids"] = [ObjectId(store_id) for store_id in update_data["store_ids"]]
        
        if "default_store_id" in update_data and update_data["default_store_id"]:
            update_data["default_store_id"] = ObjectId(update_data["default_store_id"])
        
        # Update user
        result = await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        # Return updated user
        return await auth_service.get_user_by_id(user_id)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_user(
    user_id: str,
    current_user: UserResponse = Depends(require_user_management_permission),
    auth_service: AuthService = Depends(get_auth_service),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Deactivate user (soft delete)"""
    try:
        # Check if user exists and belongs to same organization
        existing_user = await auth_service.get_user_by_id(user_id)
        if not existing_user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        if existing_user.organization_id != current_user.organization_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        # Deactivate user
        result = await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"is_active": False}}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{user_id}/activate", response_model=UserResponse)
async def activate_user(
    user_id: str,
    current_user: UserResponse = Depends(require_user_management_permission),
    auth_service: AuthService = Depends(get_auth_service),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Activate user"""
    try:
        # Check if user exists and belongs to same organization
        existing_user = await auth_service.get_user_by_id(user_id)
        if not existing_user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        if existing_user.organization_id != current_user.organization_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        # Activate user
        result = await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"is_active": True}}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        # Return updated user
        return await auth_service.get_user_by_id(user_id)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/search/{query}")
async def search_users(
    query: str,
    current_user: UserResponse = Depends(require_manager_permission),
    db: AsyncIOMotorDatabase = Depends(get_database),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Search users by name, username, or email"""
    search_query = {
        "organization_id": ObjectId(current_user.organization_id),
        "$or": [
            {"username": {"$regex": query, "$options": "i"}},
            {"full_name": {"$regex": query, "$options": "i"}},
            {"email": {"$regex": query, "$options": "i"}},
        ]
    }
    
    users_cursor = db.users.find(search_query).limit(20)
    users = await users_cursor.to_list(length=20)
    
    # Get organization info for serialization
    org_doc = await db.organizations.find_one({"_id": ObjectId(current_user.organization_id)})
    
    # Serialize users
    serialized_users = []
    for user_doc in users:
        serialized_users.append(auth_service._serialize_user(user_doc, org_doc))
    
    return {
        "users": serialized_users,
        "total": len(serialized_users)
    }