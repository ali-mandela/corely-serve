import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request

# from fastapi.middleware.cors import CORSMiddleware
# from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

# from app._core.config import settings
# from app._core.database import connect_to_mongo, close_mongo_connection

# # Security middleware
# from app._core.middleware.rate_limiting import RateLimitMiddleware
# from app._core.middleware.security import (
#     SecurityMiddleware,
#     CSRFMiddleware,
#     IPWhitelistMiddleware,
#     RequestValidationMiddleware,
#     SecurityConfig,
# )


# # ABAC and audit
# from app._core.access_control.abac.policy_engine import policy_engine
# from app._core.access_control.abac.default_policies import (
#     load_default_policies_to_engine,
# )
# from app._core.audit.logger import get_audit_logger, log_security_event
# from app._core.audit.models import AuditEventType, AuditSeverity

# # Enhanced security
# from app._core.security.enhanced_auth import enhanced_jwt


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logger.info("Starting application...")

    # # Connect to database
    # await connect_to_mongo()
    # logger.info("Database connected")

    # # Load ABAC policies
    # policies_loaded = load_default_policies_to_engine(policy_engine)
    # logger.info(f"Loaded {policies_loaded} ABAC policies")

    # # starting the background tasks
    # tasks = asyncio.create_task(background_tasks())
    yield

    # # closes the background tasks
    # tasks.cancel()
    # try:
    #     await asyncio.wait_for(tasks, timeout=2.0)  # Wait max 2 seconds
    # except (asyncio.CancelledError, asyncio.TimeoutError):
    #     pass

    # # Close database connection
    # await close_mongo_connection()
    logger.info("Shutting down application...")


async def background_tasks():
    """Background tasks for maintenance"""
    # while True:
    #     try:
    #         # Clean up expired JWT sessions and keys
    #         cleanup_result = enhanced_jwt.cleanup_expired_data()
    #         if (
    #             cleanup_result["expired_sessions"] > 0
    #             or cleanup_result["expired_keys"] > 0
    #         ):
    #             logger.info(
    #                 f"Cleaned up {cleanup_result['expired_sessions']} sessions and {cleanup_result['expired_keys']} keys"
    #             )

    #         # Rotate JWT keys if needed
    #         if enhanced_jwt.key_manager.should_rotate():
    #             new_key_id = enhanced_jwt.rotate_keys()
    #             logger.info(f"JWT keys rotated to {new_key_id}")
    #             await log_security_event(
    #                 event_type=AuditEventType.CONFIGURATION_CHANGE,
    #                 description="JWT signing keys rotated",
    #                 user_id="system",
    #                 ip_address="127.0.0.1",
    #                 severity=AuditSeverity.MEDIUM,
    #             )

    #         # Clean up old audit logs (retain for 1 year)
    #         audit_logger = await get_audit_logger()
    #         cleaned_events = await audit_logger.cleanup_old_events(365)
    #         if cleaned_events > 0:
    #             logger.info(f"Cleaned up {cleaned_events} old audit events")

    #         # Sleep for 1 hour
    #         await asyncio.sleep(3600)

    #     except Exception as e:
    #         logger.error(f"Error in background tasks: {e}")
    #         await asyncio.sleep(300)  # Wait 5 minutes on error


def create_enterprise_app() -> FastAPI:
    """Create enterprise FastAPI application with security features"""

    app = FastAPI(
        title="Enterprise Multi-Tenant System",
        description="Secure, scalable, multi-tenant retail management system with ABAC",
        version="1.0.0",
        # docs_url="/api/docs" if settings.debug else None,
        lifespan=lifespan,
    )

    # Security configuration
    # security_config = SecurityConfig()

    # Add CORS middleware first (IMPORTANT: Must be before other middleware)
    # app.add_middleware(
    #     CORSMiddleware,
    #     allow_origins=security_config.ALLOWED_ORIGINS,
    #     allow_credentials=security_config.ALLOW_CREDENTIALS,
    #     allow_methods=security_config.ALLOWED_METHODS,
    #     allow_headers=security_config.ALLOWED_HEADERS,
    #     expose_headers=[
    #         "X-RateLimit-Limit",
    #         "X-RateLimit-Remaining",
    #         "X-RateLimit-Reset",
    #     ],
    # )

    # Add trusted host middleware
    # app.add_middleware(
    #     TrustedHostMiddleware,
    #     allowed_hosts=["localhost", "127.0.0.1", "*.yourdomain.com"],
    # )

    # # Add comprehensive security middleware
    # app.add_middleware(SecurityMiddleware, config=security_config)

    # # Add request validation middleware
    # app.add_middleware(RequestValidationMiddleware)

    # # Add rate limiting middleware
    # app.add_middleware(RateLimitMiddleware)

    # # Add CSRF protection for non-API requests (disable for development)
    # if not settings.debug:
    #     app.add_middleware(CSRFMiddleware, secret_key=settings.secret_key)
    # #
    # # Add IP whitelist for admin endpoints
    # if hasattr(settings, "admin_ip_whitelist") and settings.admin_ip_whitelist:
    #     app.add_middleware(
    #         IPWhitelistMiddleware,
    #         whitelist=settings.admin_ip_whitelist,
    #         protected_paths=["/api/v1/admin", "/api/v1/organizations"],
    #     )

    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        """Global exception handler with security logging"""
        logger.error(f"Unhandled exception: {exc}", exc_info=True)

        # await log_security_event(
        #     event_type=AuditEventType.SYSTEM_ERROR,
        #     description=f"Unhandled exception: {str(exc)[:200]}",
        #     user_id=getattr(request.state, "user_id", None),
        #     ip_address=getattr(request.state, "client_ip", "unknown"),
        #     severity=AuditSeverity.HIGH,
        # )
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal server error",
                "message": "An unexpected error occurred",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request_id": getattr(request.state, "request_id", "unknown"),
            },
        )

    # Health check endpoint
    @app.get("/health")
    def health_check():
        """Health check endpoint"""
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0.0",
            # "environment": "production" if not setti/ngs.debug else "development",
        }

    return app


# # Create the app instance
app = create_enterprise_app()
