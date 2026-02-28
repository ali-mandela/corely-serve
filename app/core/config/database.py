from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from .corely_settings import CorelySettings
from app.utils.logger import Logger

db_logger = Logger(__name__)


# class DatabaseManager:
#     """MongoDB database manager"""

#     def __init__(self):
#         self.settings = CorelySettings()
#         self.client: AsyncIOMotorClient | None = None
#         self.database = None
#         self._is_connected = False  # Avoid conflict with method name

#     async def connect(self):
#         """Connect to MongoDB"""
#         try:
#             mongodb_uri = self.settings.effective_mongodb_uri
#             self.client = AsyncIOMotorClient(mongodb_uri)
#             self.database = self.client[self.settings.database_name]

#             # Test the connection
#             await self.client.admin.command("ping")

#             self._is_connected = True
#             db_logger.info("Connected to MongoDB")
#         except Exception as e:
#             self._is_connected = False
#             db_logger.error(f"Failed to connect to MongoDB: {e}")

#     async def close(self):
#         """Close database connection"""
#         if self.client:
#             self.client.close()
#             self._is_connected = False
#             db_logger.info("Database connection closed")

#     def get_database(self):
#         """Get database instance"""
#         return self.database

#     def is_connected(self) -> bool:
#         """Return whether the database is connected"""
#         return self._is_connected


class DatabaseManager:
    def __init__(self):
        self.settings = CorelySettings()
        self.client: AsyncIOMotorClient = None
        self.database = None
        self._is_connected = False  # rename to avoid conflict

    async def connect(self):
        try:
            self.client = AsyncIOMotorClient(self.settings.effective_mongodb_uri)
            self.database = self.client[self.settings.database_name]
            await self.client.admin.command("ping")
            self._is_connected = True
            print("Connected to MongoDB")
        except Exception as e:
            self._is_connected = False
            print(f"Failed to connect: {e}")

    def closeConnection(self):
        if self.client:
            self.client.close()
            self._is_connected = False
            print("Database connection closed")

    def get_database(self):
        return self.database

    def is_connected(self):
        return self._is_connected


# Module-level singleton
db_manager = DatabaseManager()


# FastAPI dependency
async def get_database() -> AsyncIOMotorDatabase:
    await db_manager.connect()
    return db_manager.database
