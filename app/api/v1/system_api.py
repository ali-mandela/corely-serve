from fastapi import APIRouter
from datetime import datetime, timezone
import platform

system = APIRouter()

@system.get("/health")
async def health_check():
    """
    Health check endpoint to verify API status.
    Returns status, timestamp, and basic system info.
    """
    return {
        "status": "online",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0",
        "system": platform.system()
    }
