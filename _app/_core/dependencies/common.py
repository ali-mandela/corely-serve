"""
Common dependencies for FastAPI application
"""
import logging
from typing import Dict, Any, Optional
from fastapi import Request, Depends, HTTPException, status
from uuid import uuid4

from ..config import get_settings, Settings
from ..utils import generate_correlation_id

logger = logging.getLogger(__name__)


async def get_request_id(request: Request) -> str:
    """
    Get or generate request ID
    """
    request_id = request.headers.get("x-request-id")
    if not request_id:
        request_id = str(uuid4())
    return request_id


async def get_client_ip(request: Request) -> str:
    """
    Get client IP address with X-Forwarded-For support
    """
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # Take the first IP in case of multiple proxies
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip

    if request.client:
        return request.client.host

    return "unknown"


async def get_user_agent(request: Request) -> str:
    """
    Get user agent string
    """
    return request.headers.get("user-agent", "unknown")


async def get_correlation_id(request: Request) -> str:
    """
    Get or generate correlation ID for request tracing
    """
    correlation_id = request.headers.get("x-correlation-id")
    if not correlation_id:
        correlation_id = generate_correlation_id()
    return correlation_id


class RequestContext:
    """
    Request context containing common request information
    """
    def __init__(
        self,
        request_id: str,
        correlation_id: str,
        client_ip: str,
        user_agent: str,
        method: str,
        path: str,
        query_params: dict
    ):
        self.request_id = request_id
        self.correlation_id = correlation_id
        self.client_ip = client_ip
        self.user_agent = user_agent
        self.method = method
        self.path = path
        self.query_params = query_params

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "client_ip": self.client_ip,
            "user_agent": self.user_agent,
            "method": self.method,
            "path": self.path,
            "query_params": self.query_params
        }


async def get_request_context(
    request: Request,
    request_id: str = Depends(get_request_id),
    correlation_id: str = Depends(get_correlation_id),
    client_ip: str = Depends(get_client_ip),
    user_agent: str = Depends(get_user_agent)
) -> RequestContext:
    """
    Get comprehensive request context
    """
    return RequestContext(
        request_id=request_id,
        correlation_id=correlation_id,
        client_ip=client_ip,
        user_agent=user_agent,
        method=request.method,
        path=str(request.url.path),
        query_params=dict(request.query_params)
    )


# Content type validators
async def validate_json_content_type(request: Request):
    """
    Validate that request has JSON content type
    """
    content_type = request.headers.get("content-type", "")
    if not content_type.startswith("application/json"):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Content-Type must be application/json"
        )


# API versioning
class APIVersion:
    def __init__(self, version: str):
        self.version = version

    def __call__(self, request: Request) -> str:
        # Check header first
        api_version = request.headers.get("api-version")
        if api_version:
            return api_version

        # Check query parameter
        api_version = request.query_params.get("v")
        if api_version:
            return api_version

        # Return default version
        return self.version


# Common API version dependencies
api_v1 = APIVersion("v1")
api_v2 = APIVersion("v2")


# Health check dependency
async def health_check() -> Dict[str, str]:
    """
    Basic health check
    """
    return {"status": "healthy", "service": "lhs-backend"}


# Environment checking
class EnvironmentCheck:
    def __init__(self, allowed_envs: list):
        self.allowed_envs = allowed_envs

    async def __call__(self, settings: Settings = Depends(get_settings)):
        if settings.ENVIRONMENT not in self.allowed_envs:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This endpoint is not available in {settings.ENVIRONMENT} environment"
            )
        return settings


# Environment-specific dependencies
dev_only = EnvironmentCheck(["development", "testing"])
dev_test_only = EnvironmentCheck(["development", "testing"])
prod_only = EnvironmentCheck(["production"])


# Request size limiter
class RequestSizeLimiter:
    def __init__(self, max_size_mb: int = 10):
        self.max_size_bytes = max_size_mb * 1024 * 1024

    async def __call__(self, request: Request):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_size_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Request too large. Maximum size: {self.max_size_bytes // (1024*1024)}MB"
            )
        return request


# Common size limiters
small_request_limit = RequestSizeLimiter(1)  # 1MB
medium_request_limit = RequestSizeLimiter(10)  # 10MB
large_request_limit = RequestSizeLimiter(50)  # 50MB


# Feature flag dependency
class FeatureFlag:
    def __init__(self, feature_name: str, default: bool = False):
        self.feature_name = feature_name
        self.default = default

    async def __call__(self, settings: Settings = Depends(get_settings)) -> bool:
        # This would typically check a feature flag service
        # For now, we'll check environment variables
        import os
        flag_value = os.getenv(f"FEATURE_{self.feature_name.upper()}", str(self.default))
        return flag_value.lower() in ("true", "1", "yes", "on")


# Common feature flags
new_ui_enabled = FeatureFlag("NEW_UI", False)
advanced_analytics = FeatureFlag("ADVANCED_ANALYTICS", False)
beta_features = FeatureFlag("BETA_FEATURES", False)


# Time zone dependency
async def get_timezone(request: Request) -> str:
    """
    Get timezone from request headers or default to UTC
    """
    timezone = request.headers.get("x-timezone", "UTC")
    # Validate timezone if needed
    return timezone


# Language/locale dependency
async def get_locale(request: Request) -> str:
    """
    Get locale from Accept-Language header or default
    """
    accept_language = request.headers.get("accept-language", "en-US")
    # Parse and return primary language
    return accept_language.split(",")[0].split(";")[0].strip()


# Device type detection
class DeviceType:
    MOBILE = "mobile"
    TABLET = "tablet"
    DESKTOP = "desktop"
    BOT = "bot"


async def get_device_type(user_agent: str = Depends(get_user_agent)) -> str:
    """
    Detect device type from user agent
    """
    user_agent_lower = user_agent.lower()

    if any(bot in user_agent_lower for bot in ["bot", "crawler", "spider", "scraper"]):
        return DeviceType.BOT

    if any(mobile in user_agent_lower for mobile in ["mobile", "android", "iphone"]):
        return DeviceType.MOBILE

    if any(tablet in user_agent_lower for tablet in ["tablet", "ipad"]):
        return DeviceType.TABLET

    return DeviceType.DESKTOP