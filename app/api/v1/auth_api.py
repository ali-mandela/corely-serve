# app/api/v1/auth_api.py
from fastapi import APIRouter, Depends, Request
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.core.config.database import get_database
from app.service.auth_service import AuthService
from app.schema.user_schema import UserLogin
from app.utils.helpers import success_response, error_response

auth = APIRouter()


async def get_service(db: AsyncIOMotorDatabase = Depends(get_database)) -> AuthService:
    return AuthService(db)


@auth.post("/login")
async def login_user(
    request: Request, user: UserLogin, service: AuthService = Depends(get_service)
):
    try:
        if not request.state.organization and request.state.organization["is_active"]:
            error_response(message="Orgnaization not found", code=404)

        res = await service.authenticate_user(user, request.state.organization)

        print(res)
        print("YES USER")

        pass
    except Exception as e:
        error_response(message=e.message, code=500, data=e)
