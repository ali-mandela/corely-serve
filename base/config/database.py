from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from .settings import settings


class DatabaseManager:
    """MongoDB connection manager — true singleton."""

    _instance = None
    _client: AsyncIOMotorClient | None = None
    _database: AsyncIOMotorDatabase | None = None
    _connected: bool = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    async def connect(self) -> None:
        if self._connected:
            return
        try:
            self._client = AsyncIOMotorClient(settings.mongodb_atlas_uri)
            self._database = self._client[settings.database_name]
            await self._client.admin.command("ping")
            self._connected = True
            print(f"[OK] Connected to MongoDB [{settings.database_name}]")
        except Exception as e:
            self._connected = False
            print(f"[ERROR] Failed to connect to MongoDB: {e}")
            raise

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._connected = False
            self._client = None
            self._database = None
            print("[CLOSED] MongoDB connection closed")

    @property
    def database(self) -> AsyncIOMotorDatabase:
        if self._database is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._database

    @property
    def is_connected(self) -> bool:
        return self._connected


# ── Module-level singleton ──────────────────────────────────────
db_manager = DatabaseManager()


async def get_database() -> AsyncIOMotorDatabase:
    """FastAPI dependency — returns the database instance."""
    if not db_manager.is_connected:
        await db_manager.connect()
    return db_manager.database
