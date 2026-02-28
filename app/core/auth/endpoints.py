from fastapi import APIRouter, Depends, Request, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.core.config.database import get_database
from .auth_service import AuthService
from .schema import UserLogin
from app.utils.helpers import success_response, error_response


auth = APIRouter()


async def get_service(db: AsyncIOMotorDatabase = Depends(get_database)) -> AuthService:
    return AuthService(db)


@auth.post("/login")
async def login_user(
    request: Request, user: UserLogin, service: AuthService = Depends(get_service)
):
    try:
        return await service.authenticate_user(user)
    except HTTPException as e:
        raise e
    except Exception as e:
        return error_response(message="Internal server errorrr", code=500, data=str(e))
