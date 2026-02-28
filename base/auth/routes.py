from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase

from base.config import get_database
from base.utils import success_response
from .schemas import LoginRequest
from .service import AuthService

auth_router = APIRouter()


@auth_router.post("/login")
async def login(
    body: LoginRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Authenticate user and return JWT + user data."""
    svc = AuthService(db)
    result = await svc.authenticate(
        identifier=body.identifier,
        password=body.password,
        slug=body.slug,
    )
    return success_response(data=result, message="Login successful")
