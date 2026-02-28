# app/service/auth_service.py
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorClient
from fastapi.responses import JSONResponse
from app.utils.helpers import success_response, error_response


class AuthService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.users = db.users

    async def authenticate_user(self, user_data):
        # Try finding user
        user = await self.users.find_one(
            {"$or": [{"email": user_data.identifier}, {"phone": user_data.identifier}]}
        )
        if not user:
            return success_response(message="user not found", code=404)

        # check for password
        print("Found user:", user)

    #     def hash_password(password: str) -> str:
    # salt = secrets.token_hex(16)
    # password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    # return f"{salt}:{password_hash}"
        return user
