from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from typing import Optional
import os
from app.core.config.corely_settings import CorelySettings

_client: Optional[AsyncIOMotorClient] = None


settings = CorelySettings()


async def get_database() -> AsyncIOMotorDatabase:
    """Get or create a MongoDB connection for auth module."""
    global _client
    if _client is None:
        mongo_uri = settings.effective_mongodb_uri
        _client = AsyncIOMotorClient(mongo_uri)
    return _client.get_database(os.getenv("AUTH_DB_NAME", "auth_db"))


async def get_collection(collection: str):
    """Return the users collection."""
    db = await get_database()
    return db.get_collection(collection)
