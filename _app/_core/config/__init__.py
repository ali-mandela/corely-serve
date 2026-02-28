"""
Enterprise Multi-Tenant Stores Management System - Configuration Module
This module provides all configuration management functionality including
environment detection, settings management, and database connections.
"""

from typing import Optional

# Version info
__version__ = "1.0.0"
__author__ = "Enterprise Stores Management Team"
__description__ = (
    "Configuration management for India-based enterprise stores management system"
)

# Import environment configuration
from .environment import (
    Environment,
    EnvironmentConfig,
    DatabaseEnvironmentConfig,
    RedisEnvironmentConfig,
    SecurityEnvironmentConfig,
    LoggingEnvironmentConfig,
    APIEnvironmentConfig,
    ExternalServicesConfig,
    MonitoringConfig,
    get_environment_config,
    get_current_environment,
    is_development,
    is_production,
)

# Import settings configuration
from .settings import (
    AppSettings,
    DatabaseSettings,
    CacheSettings,
    RedisSettings,
    SecuritySettings,
    APISettings,
    TenantSettings,
    BusinessSettings,
    ExternalServicesSettings,
    RateLimitSettings,
    MonitoringSettings,
    LoggingSettings,
    get_settings,
    settings,
)

# Import database configuration
from .database import (
    DatabaseManager,
    TenantDatabaseManager,
    ConnectionPool,
    get_connection_pool,
    get_database,
    get_collection,
    get_tenant_collection,
    create_tenant_indexes,
    database_health_check,
    close_database_connections,
    ensure_indexes,
)


# ================== CONFIGURATION MANAGEMENT ==================


class ConfigManager:
    """Central configuration manager for the application"""

    def __init__(self):
        self._env_config = get_environment_config()
        self._app_settings = get_settings()
        self._db_pool = None
        self._initialized = False

    @property
    def environment(self) -> Environment:
        """Get current environment"""
        return self._env_config.current

    @property
    def settings(self) -> AppSettings:
        """Get application settings"""
        return self._app_settings

    @property
    def is_development(self) -> bool:
        """Check if running in development"""
        return self._env_config.is_development()

    @property
    def is_production(self) -> bool:
        """Check if running in production"""
        return self._env_config.is_production()

    async def initialize(self) -> None:
        """Initialize configuration and connections"""
        if self._initialized:
            return

        try:
            print(
                f"🚀 Initializing configuration for {self.environment.value} environment..."
            )

            # Initialize database connection
            await self._initialize_database()

            # Validate configuration
            await self._validate_configuration()

            self._initialized = True
            print(f"✅ Configuration initialized successfully")

        except Exception as e:
            print(f"❌ Configuration initialization failed: {str(e)}")
            raise

    async def _initialize_database(self) -> None:
        """Initialize database connections"""
        try:
            self._db_pool = await get_connection_pool()

            # Ensure core indexes
            await ensure_indexes()

            print("✅ Database connection initialized")

        except Exception as e:
            print(f"❌ Database initialization failed: {str(e)}")
            raise

    async def _validate_configuration(self) -> None:
        """Validate configuration settings"""
        validation_errors = []

        # Validate database configuration
        if not self.settings.database.atlas_connection_string:
            if not all(
                [
                    self.settings.database.host,
                    self.settings.database.database,
                    self.settings.database.username,
                    self.settings.database.password,
                ]
            ):
                validation_errors.append("Database configuration incomplete")

        # Validate security settings in production
        if self.is_production:
            if len(self.settings.security.secret_key) < 32:
                validation_errors.append("Secret key too short for production")

            if not self.settings.security.require_https:
                validation_errors.append("HTTPS should be required in production")

            if not self.settings.security.require_mfa:
                validation_errors.append("MFA should be required in production")

        # Validate external services
        if self.settings.external_services.payment_provider == "razorpay":
            if not self.settings.external_services.razorpay_key:
                validation_errors.append("Razorpay API key not configured")

        if validation_errors:
            error_msg = "Configuration validation failed:\n" + "\n".join(
                f"- {error}" for error in validation_errors
            )
            raise ValueError(error_msg)

    async def health_check(self) -> dict:
        """Perform comprehensive health check"""
        health_status = {
            "status": "healthy",
            "timestamp": get_current_timestamp(),
            "environment": self.environment.value,
            "components": {},
        }

        # Database health
        try:
            db_health = await database_health_check()
            health_status["components"]["database"] = db_health
        except Exception as e:
            health_status["components"]["database"] = {
                "status": "unhealthy",
                "error": str(e),
            }
            health_status["status"] = "unhealthy"

        # Configuration health
        try:
            config_health = self._check_config_health()
            health_status["components"]["configuration"] = config_health
        except Exception as e:
            health_status["components"]["configuration"] = {
                "status": "unhealthy",
                "error": str(e),
            }
            health_status["status"] = "unhealthy"

        # External services health
        try:
            services_health = self._check_services_health()
            health_status["components"]["external_services"] = services_health
        except Exception as e:
            health_status["components"]["external_services"] = {
                "status": "unhealthy",
                "error": str(e),
            }
            health_status["status"] = "unhealthy"

        return health_status

    def _check_config_health(self) -> dict:
        """Check configuration health"""
        issues = []

        # Check critical settings
        if not self.settings.security.secret_key:
            issues.append("Missing secret key")

        if self.is_production and self.settings.api.debug:
            issues.append("Debug mode enabled in production")

        if not self.settings.database.connection_url:
            issues.append("Database connection not configured")

        return {
            "status": "healthy" if not issues else "degraded",
            "issues": issues,
            "environment": self.environment.value,
            "initialized": self._initialized,
        }

    def _check_services_health(self) -> dict:
        """Check external services configuration health"""
        services_status = {}

        # Payment service
        if self.settings.external_services.razorpay_key:
            services_status["payment"] = "configured"
        else:
            services_status["payment"] = "not_configured"

        # Email service
        if self.settings.external_services.smtp_host:
            services_status["email"] = "configured"
        else:
            services_status["email"] = "not_configured"

        # SMS service
        if self.settings.external_services.msg91_api_key:
            services_status["sms"] = "configured"
        else:
            services_status["sms"] = "not_configured"

        # Storage service
        services_status["storage"] = self.settings.external_services.storage_provider

        # Maps service
        if self.settings.external_services.google_maps_api_key:
            services_status["maps"] = "configured"
        else:
            services_status["maps"] = "not_configured"

        return {"status": "healthy", "services": services_status}

    async def shutdown(self) -> None:
        """Cleanup configuration and connections"""
        try:
            print("🛑 Shutting down configuration...")

            if self._db_pool:
                await close_database_connections()

            self._initialized = False
            print("✅ Configuration shutdown complete")

        except Exception as e:
            print(f"❌ Error during configuration shutdown: {str(e)}")


# ================== UTILITY FUNCTIONS ==================


def get_current_timestamp() -> str:
    """Get current timestamp in ISO format"""
    from datetime import datetime

    return datetime.utcnow().isoformat()


def get_config_summary() -> dict:
    """Get configuration summary for debugging"""
    config_manager = ConfigManager()
    settings = config_manager.settings

    return {
        "environment": config_manager.environment.value,
        "debug_mode": settings.api.debug,
        "database": {
            "provider": (
                "mongodb_atlas"
                if settings.database.atlas_connection_string
                else "mongodb"
            ),
            "database_name": settings.database.database,
            "max_connections": settings.database.max_connections,
        },
        "cache": {
            "enabled": settings.cache.enabled,
            "provider": settings.cache.provider,
        },
        "security": {
            "require_https": settings.security.require_https,
            "require_mfa": settings.security.require_mfa,
            "session_timeout": settings.security.session_expire_hours,
        },
        "features": {
            "multi_tenant": True,
            "rate_limiting": settings.rate_limit.enabled,
            "monitoring": settings.monitoring.enabled,
        },
        "external_services": {
            "payment": settings.external_services.payment_provider,
            "storage": settings.external_services.storage_provider,
            "email": settings.external_services.email_provider,
            "sms": settings.external_services.sms_provider,
        },
    }


def validate_environment_setup() -> dict:
    """Validate environment setup and return status"""
    import os

    validation_result = {
        "valid": True,
        "warnings": [],
        "errors": [],
        "environment_variables": {},
    }

    # Critical environment variables
    critical_vars = ["MONGODB_ATLAS_URI", "SECRET_KEY", "JWT_SECRET"]

    # Optional but recommended variables
    recommended_vars = [
        "RAZORPAY_KEY",
        "RAZORPAY_SECRET",
        "SMTP_HOST",
        "SMTP_USER",
        "MSG91_API_KEY",
    ]

    # Check critical variables
    for var in critical_vars:
        value = os.getenv(var)
        if value:
            validation_result["environment_variables"][var] = "✅ Set"
        else:
            validation_result["environment_variables"][var] = "❌ Missing"
            validation_result["errors"].append(
                f"Critical environment variable {var} is missing"
            )
            validation_result["valid"] = False

    # Check recommended variables
    for var in recommended_vars:
        value = os.getenv(var)
        if value:
            validation_result["environment_variables"][var] = "✅ Set"
        else:
            validation_result["environment_variables"][var] = "⚠️ Not set"
            validation_result["warnings"].append(
                f"Recommended environment variable {var} is not set"
            )

    # Environment-specific validations
    env = os.getenv("ENVIRONMENT", "development").lower()
    if env == "production":
        prod_vars = ["PROD_SECRET_KEY", "PROD_DB_HOST"]
        for var in prod_vars:
            if not os.getenv(var):
                validation_result["warnings"].append(
                    f"Production variable {var} not set"
                )

    return validation_result


def print_startup_banner() -> None:
    """Print application startup banner"""
    config_manager = ConfigManager()

    banner = f"""
╔═══════════════════════════════════════════════════════════════╗
║                    STORES MANAGEMENT SYSTEM                   ║
║                   Enterprise Multi-Tenant                     ║
╠═══════════════════════════════════════════════════════════════╣
║ Environment: {config_manager.environment.value.upper():^15}   ║
║ Version:     {__version__:^15}                                ║
║ Database:    MongoDB Atlas                                    ║
║ Region:      India (🇮🇳)                                       ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(banner)


# ================== GLOBAL CONFIGURATION INSTANCE ==================

# Global configuration manager instance
_config_manager: Optional[ConfigManager] = None


def get_config_manager() -> ConfigManager:
    """Get the global configuration manager instance"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


async def initialize_application() -> None:
    """Initialize the entire application configuration"""
    config_manager = get_config_manager()
    await config_manager.initialize()


async def shutdown_application() -> None:
    """Shutdown the application configuration"""
    global _config_manager
    if _config_manager:
        await _config_manager.shutdown()
        _config_manager = None


# ================== CONVENIENCE IMPORTS ==================

# Most commonly used imports for easy access
from .settings import settings
from .environment import get_current_environment, is_development, is_production
from .database import get_database, get_collection, get_tenant_collection

# Export commonly used items
__all__ = [
    # Configuration management
    "ConfigManager",
    "get_config_manager",
    "initialize_application",
    "shutdown_application",
    # Environment
    "Environment",
    "get_current_environment",
    "is_development",
    "is_production",
    # Settings
    "AppSettings",
    "get_settings",
    "settings",
    # Database
    "get_database",
    "get_collection",
    "get_tenant_collection",
    "database_health_check",
    "create_tenant_indexes",
    # Utilities
    "get_config_summary",
    "validate_environment_setup",
    "print_startup_banner",
    # All settings classes
    "DatabaseSettings",
    "CacheSettings",
    "RedisSettings",
    "SecuritySettings",
    "APISettings",
    "TenantSettings",
    "BusinessSettings",
    "ExternalServicesSettings",
    "RateLimitSettings",
    "MonitoringSettings",
    "LoggingSettings",
    # All environment config classes
    "EnvironmentConfig",
    "DatabaseEnvironmentConfig",
    "RedisEnvironmentConfig",
    "SecurityEnvironmentConfig",
    "LoggingEnvironmentConfig",
    "APIEnvironmentConfig",
    "ExternalServicesConfig",
    "MonitoringConfig",
]


# Module initialization
def _init_message():
    """Print initialization message in development"""
    import os

    if os.getenv("ENVIRONMENT", "development") == "development":
        print(f"✅ Core Config Module v{__version__} initialized")
        print(f"🔧 Environment: {get_current_environment().value}")
        print(f"🗃️ Database: MongoDB Atlas")
        print(f"🇮🇳 Region: India")


# Call init message
_init_message()
