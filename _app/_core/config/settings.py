"""
Enterprise Multi-Tenant Stores Management System - Main Application Settings
This module contains the main application configuration and settings management.
"""

import os
import secrets
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
from functools import lru_cache

from pydantic_settings import BaseSettings
from pydantic import validator, Field

from app._core.config.environment import (
    get_current_environment,
    DatabaseEnvironmentConfig,
    RedisEnvironmentConfig,
    SecurityEnvironmentConfig,
    APIEnvironmentConfig,
    ExternalServicesConfig,
    LoggingEnvironmentConfig,
    MonitoringConfig,
    Environment,
)
from app._core.utils.constants import (
    TenantConstants,
    AuthConstants,
    SecurityConstants,
    BusinessConstants,
    RateLimitConstants,
)


class DatabaseSettings(BaseSettings):
    """Database configuration settings"""

    # MongoDB Settings (Atlas Free Tier Optimized)
    host: str = Field(default="localhost", env="DB_HOST")
    port: int = Field(default=27017, env="DB_PORT")
    database: str = Field(default="stores_management", env="DB_NAME")
    username: Optional[str] = Field(default=None, env="DB_USER")
    password: Optional[str] = Field(default=None, env="DB_PASS")

    # Atlas Connection String (for MongoDB Atlas)
    atlas_connection_string: Optional[str] = Field(
        default=None, env="MONGODB_ATLAS_URI"
    )

    # Connection Pool Settings (Optimized for Atlas Free Tier)
    max_connections: int = 10  # Reduced for free tier limits
    min_connections: int = 2  # Minimal connections
    connection_timeout: int = 30
    query_timeout: int = 60
    retry_attempts: int = 3
    retry_delay: int = 1

    # Advanced Settings
    enable_ssl: bool = False
    enable_replication: bool = False
    replica_set: Optional[str] = None
    read_preference: str = "primary"
    write_concern: Optional[Dict[str, Any]] = None
    read_concern: Optional[Dict[str, str]] = None

    # Development Settings
    enable_query_logging: bool = False
    slow_query_threshold: float = 2.0
    enable_profiling: bool = False
    log_level: str = "INFO"

    @property
    def connection_url(self) -> str:
        """Build MongoDB connection URL (Atlas-friendly)"""
        # If Atlas connection string is provided, use it directly
        if self.atlas_connection_string:
            return self.atlas_connection_string

        # Fallback to manual connection for local development
        auth_part = ""
        if self.username and self.password:
            auth_part = f"{self.username}:{self.password}@"

        base_url = f"mongodb://{auth_part}{self.host}:{self.port}/{self.database}"

        # Add query parameters
        params = []
        if self.replica_set:
            params.append(f"replicaSet={self.replica_set}")
        if self.enable_ssl:
            params.append("ssl=true")
        if self.read_preference != "primary":
            params.append(f"readPreference={self.read_preference}")

        if params:
            base_url += "?" + "&".join(params)

        return base_url

        # _part = f":{self.password}@" if self.password else ""
        #         protocol = "rediss" if self.ssl else "redis"
        #         return f"{protocol}://{auth_part}{self.host}:{self.port}/{self.db}"


class SecuritySettings(BaseSettings):
    """Security configuration settings"""

    # Core Security
    secret_key: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32), env="SECRET_KEY"
    )
    jwt_secret: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32), env="JWT_SECRET"
    )
    encryption_key: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32), env="ENCRYPTION_KEY"
    )

    # Session Management
    session_expire_hours: int = AuthConstants.SESSION_EXPIRE_HOURS
    max_sessions_per_user: int = AuthConstants.MAX_SESSIONS_PER_USER
    force_logout_inactive_days: int = 30

    # Password Policy
    password_min_length: int = AuthConstants.MIN_PASSWORD_LENGTH
    password_max_length: int = AuthConstants.MAX_PASSWORD_LENGTH
    require_uppercase: bool = AuthConstants.REQUIRE_UPPERCASE
    require_lowercase: bool = AuthConstants.REQUIRE_LOWERCASE
    require_numbers: bool = AuthConstants.REQUIRE_NUMBERS
    require_special_chars: bool = AuthConstants.REQUIRE_SPECIAL_CHARS
    require_password_change_days: int = 90

    # Authentication
    max_login_attempts: int = 3
    lockout_duration_minutes: int = 30
    require_mfa: bool = False
    require_email_verification: bool = True

    # CORS Settings
    allowed_origins: List[str] = []
    cors_allow_credentials: bool = True
    cors_allow_methods: List[str] = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
    cors_allow_headers: List[str] = ["*"]

    # Security Headers
    require_https: bool = False
    csrf_protection: bool = True
    security_headers: Dict[str, Any] = {}

    # Development Settings
    debug_toolbar: bool = False
    allow_test_users: bool = False

    @validator("secret_key", "jwt_secret", "encryption_key")
    def validate_secrets(cls, v):
        if not v or len(v) < 32:
            raise ValueError("Security keys must be at least 32 characters long")
        return v


class APISettings(BaseSettings):
    """API configuration settings"""

    # Basic API Info
    title: str = "Enterprise Stores Management API"
    description: str = "Multi-Tenant Stores Management System for India"
    version: str = "1.0.0"

    # Server Settings
    host: str = Field(default="0.0.0.0", env="API_HOST")
    port: int = Field(default=8000, env="API_PORT")
    workers: int = Field(default=1, env="API_WORKERS")

    # Documentation
    docs_url: Optional[str] = "/docs"
    redoc_url: Optional[str] = "/redoc"
    openapi_url: Optional[str] = "/openapi.json"

    # Features
    debug: bool = False
    reload: bool = False
    include_admin_routes: bool = False
    include_debug_routes: bool = False
    include_metrics: bool = True

    # Performance
    keep_alive: int = 65
    max_requests: int = 1000
    max_requests_jitter: int = 100
    preload_app: bool = False

    # Proxy Settings
    proxy_headers: bool = False
    forwarded_allow_ips: str = "127.0.0.1"

    # Contact & License
    contact: Dict[str, str] = {
        "name": "API Support",
        "email": "api-support@yourdomain.com",
    }
    license_info: Dict[str, str] = {
        "name": "Proprietary",
        "url": "https://yourdomain.com/license",
    }


class TenantSettings(BaseSettings):
    """Multi-tenant configuration settings"""

    # Tenant Limits
    max_tenants_per_organization: int = TenantConstants.MAX_TENANTS_PER_ORGANIZATION
    default_tenant_plan: str = TenantConstants.DEFAULT_TENANT_PLAN

    # Plan Configurations
    plan_limits: Dict[str, Dict[str, int]] = TenantConstants.PLAN_LIMITS

    # Tenant Features
    enable_subdomain_routing: bool = True
    enable_custom_domains: bool = False
    enable_tenant_branding: bool = True
    enable_tenant_analytics: bool = True

    # Data Isolation
    tenant_isolation_level: str = "database"  # database, schema, or row
    enable_cross_tenant_queries: bool = False
    tenant_data_encryption: bool = True

    # Billing & Subscriptions
    enable_billing: bool = True
    billing_cycle: str = "monthly"  # monthly, annual
    trial_period_days: int = 30
    grace_period_days: int = 7

    # Tenant Creation
    require_admin_approval: bool = False
    auto_provision_resources: bool = True
    default_tenant_features: List[str] = [
        "basic_pos",
        "inventory_management",
        "employee_management",
        "customer_management",
        "basic_reports",
    ]


class BusinessSettings(BaseSettings):
    """Business logic configuration settings"""

    # Pagination
    default_page_size: int = BusinessConstants.DEFAULT_PAGE_SIZE
    max_page_size: int = BusinessConstants.MAX_PAGE_SIZE

    # File Operations
    max_file_size: int = BusinessConstants.MAX_PRODUCT_IMAGE_SIZE
    max_document_size: int = BusinessConstants.MAX_DOCUMENT_SIZE
    max_bulk_import_size: int = BusinessConstants.MAX_BULK_IMPORT_SIZE

    # Business Rules
    low_stock_threshold: int = BusinessConstants.LOW_STOCK_NOTIFICATION_THRESHOLD
    high_value_transaction_threshold: int = (
        BusinessConstants.HIGH_VALUE_TRANSACTION_THRESHOLD
    )
    daily_sales_target_variance: float = BusinessConstants.DAILY_SALES_TARGET_VARIANCE

    # Timeouts
    report_generation_timeout: int = BusinessConstants.REPORT_GENERATION_TIMEOUT
    bulk_operation_timeout: int = BusinessConstants.BULK_OPERATION_TIMEOUT

    # Inventory Management
    enable_auto_reorder: bool = True
    auto_reorder_threshold: int = 10
    enable_stock_alerts: bool = True
    stock_alert_frequency: str = "daily"  # hourly, daily, weekly

    # Financial Settings
    default_currency: str = "INR"
    default_tax_rate: float = 18.0  # GST rate
    enable_multi_currency: bool = False
    currency_precision: int = 2

    # Operational Hours
    default_business_hours: Dict[str, str] = {
        "monday": "09:00-21:00",
        "tuesday": "09:00-21:00",
        "wednesday": "09:00-21:00",
        "thursday": "09:00-21:00",
        "friday": "09:00-21:00",
        "saturday": "09:00-21:00",
        "sunday": "10:00-20:00",
    }

    # Notifications
    enable_email_notifications: bool = True
    enable_sms_notifications: bool = True
    enable_push_notifications: bool = True
    notification_retry_attempts: int = 3


class ExternalServicesSettings(BaseSettings):
    """External services configuration"""

    # Email Service
    email_provider: str = "smtp"
    smtp_host: Optional[str] = Field(default=None, env="SMTP_HOST")
    smtp_port: int = Field(default=587, env="SMTP_PORT")
    smtp_user: Optional[str] = Field(default=None, env="SMTP_USER")
    smtp_password: Optional[str] = Field(default=None, env="SMTP_PASSWORD")
    smtp_use_tls: bool = True
    from_email: str = Field(default="noreply@yourdomain.com", env="FROM_EMAIL")
    from_name: str = "Stores Management"

    # SMS Service (Indian)
    sms_provider: str = "msg91"
    msg91_api_key: Optional[str] = Field(default=None, env="MSG91_API_KEY")
    sms_sender_id: str = Field(default="STORES", env="SMS_SENDER_ID")
    sms_route: str = "4"  # Transactional route

    # Payment Gateway (Razorpay for India)
    payment_provider: str = "razorpay"
    razorpay_key: Optional[str] = Field(default=None, env="RAZORPAY_KEY")
    razorpay_secret: Optional[str] = Field(default=None, env="RAZORPAY_SECRET")
    razorpay_webhook_secret: Optional[str] = Field(
        default=None, env="RAZORPAY_WEBHOOK_SECRET"
    )
    payment_currency: str = "INR"
    payment_sandbox: bool = False

    # Storage Service (Free Hosting Optimized)
    storage_provider: str = "local"  # local for free hosting
    local_storage_path: str = "uploads/"
    max_storage_size_mb: int = 500  # 500MB limit for free hosting
    cleanup_old_files_days: int = 30  # Auto-cleanup for storage management
    aws_access_key: Optional[str] = Field(default=None, env="AWS_ACCESS_KEY")
    aws_secret_key: Optional[str] = Field(default=None, env="AWS_SECRET_KEY")
    aws_region: str = Field(default="ap-south-1", env="AWS_REGION")  # Mumbai
    s3_bucket: Optional[str] = Field(default=None, env="S3_BUCKET")
    cdn_url: Optional[str] = Field(default=None, env="CDN_URL")

    # Maps API (Google Maps for India)
    google_maps_api_key: Optional[str] = Field(default=None, env="GOOGLE_MAPS_KEY")
    enable_places_api: bool = True
    enable_geocoding_api: bool = True

    # GST API (Government of India)
    gst_api_enabled: bool = True
    gst_api_url: str = "https://api.gst.gov.in"
    gst_api_key: Optional[str] = Field(default=None, env="GST_API_KEY")
    gst_client_id: Optional[str] = Field(default=None, env="GST_CLIENT_ID")
    gst_client_secret: Optional[str] = Field(default=None, env="GST_CLIENT_SECRET")


class RateLimitSettings(BaseSettings):
    """Rate limiting configuration - Simplified for free hosting"""

    enabled: bool = Field(
        default=False, env="RATE_LIMIT_ENABLED"
    )  # Disabled by default for free hosting

    # Simple Limits (when enabled)
    requests_per_minute: int = 60
    requests_per_hour: int = 1000

    # Storage Backend (memory-based for free hosting)
    storage_backend: str = "memory"  # memory, redis
    fail_on_rate_limit: bool = True


class MonitoringSettings(BaseSettings):
    """Monitoring and observability settings"""

    # Basic Monitoring
    enabled: bool = True
    metrics_enabled: bool = True
    health_check_enabled: bool = True

    # Prometheus
    prometheus_enabled: bool = False
    prometheus_port: int = Field(default=9090, env="PROMETHEUS_PORT")

    # Application Performance Monitoring
    newrelic_enabled: bool = False
    newrelic_license_key: Optional[str] = Field(
        default=None, env="NEWRELIC_LICENSE_KEY"
    )

    # Error Tracking
    sentry_enabled: bool = False
    sentry_dsn: Optional[str] = Field(default=None, env="SENTRY_DSN")
    sentry_environment: str = "development"
    sentry_traces_sample_rate: float = 0.1

    # Custom Metrics
    custom_metrics: bool = True
    performance_monitoring: bool = True
    error_tracking: bool = True
    uptime_monitoring: bool = True

    # Health Check Endpoints
    health_check_path: str = "/health"
    ready_check_path: str = "/ready"
    metrics_path: str = "/metrics"


class LoggingSettings(BaseSettings):
    """Logging configuration settings"""

    # Basic Logging
    level: str = "INFO"
    format: str = "detailed"

    # File Logging
    enable_file_logging: bool = True
    log_file_path: str = "logs/application.log"
    log_file_max_size: int = 10 * 1024 * 1024  # 10MB
    log_file_backup_count: int = 5

    # Structured Logging
    enable_json_logging: bool = False
    include_request_id: bool = True
    include_user_id: bool = True
    include_tenant_id: bool = True

    # Special Loggers
    enable_audit_logging: bool = True
    audit_log_file: str = "logs/audit.log"
    enable_security_logging: bool = True
    security_log_file: str = "logs/security.log"

    # Performance Logging
    log_slow_queries: bool = True
    slow_query_threshold: float = 2.0
    log_performance_metrics: bool = True


class AppSettings(BaseSettings):
    """Main application settings that combines all configuration"""

    # Environment Detection
    environment: str = Field(default="development", env="ENVIRONMENT")

    # Sub-configurations
    database: DatabaseSettings = DatabaseSettings()
    cache: CacheSettings = CacheSettings()  # Added cache settings
    redis: RedisSettings = RedisSettings()
    security: SecuritySettings = SecuritySettings()
    api: APISettings = APISettings()
    tenant: TenantSettings = TenantSettings()
    business: BusinessSettings = BusinessSettings()
    external_services: ExternalServicesSettings = ExternalServicesSettings()
    rate_limit: RateLimitSettings = RateLimitSettings()
    monitoring: MonitoringSettings = MonitoringSettings()
    logging: LoggingSettings = LoggingSettings()

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

        @classmethod
        def customise_sources(
            cls,
            init_settings: SettingsSourceCallable,
            env_settings: SettingsSourceCallable,
            file_secret_settings: SettingsSourceCallable,
        ) -> tuple[SettingsSourceCallable, ...]:
            return (
                init_settings,
                env_settings,
                file_secret_settings,
            )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._apply_environment_overrides()

    def _apply_environment_overrides(self):
        """Apply environment-specific configuration overrides"""
        current_env = get_current_environment()

        # Apply database config from environment
        db_config = DatabaseEnvironmentConfig.get_config(current_env)
        for key, value in db_config.items():
            if hasattr(self.database, key):
                setattr(self.database, key, value)

        # Apply Redis config from environment
        redis_config = RedisEnvironmentConfig.get_config(current_env)
        for key, value in redis_config.items():
            if hasattr(self.redis, key):
                setattr(self.redis, key, value)

        # Apply security config from environment
        security_config = SecurityEnvironmentConfig.get_config(current_env)
        for key, value in security_config.items():
            if hasattr(self.security, key):
                setattr(self.security, key, value)

        # Apply API config from environment
        api_config = APIEnvironmentConfig.get_config(current_env)
        for key, value in api_config.items():
            if hasattr(self.api, key):
                setattr(self.api, key, value)

        # Apply external services config from environment
        services_config = ExternalServicesConfig.get_config(current_env)
        self._apply_external_services_config(services_config)

        # Apply monitoring config from environment
        monitoring_config = MonitoringConfig.get_config(current_env)
        for key, value in monitoring_config.items():
            if hasattr(self.monitoring, key):
                setattr(self.monitoring, key, value)

    def _apply_external_services_config(self, config: Dict[str, Any]):
        """Apply external services configuration"""
        # Email configuration
        if "email" in config:
            email_config = config["email"]
            self.external_services.email_provider = email_config.get("provider", "smtp")
            if "from_email" in email_config:
                self.external_services.from_email = email_config["from_email"]
            if "from_name" in email_config:
                self.external_services.from_name = email_config["from_name"]

        # Payment configuration
        if "payment" in config:
            payment_config = config["payment"]
            self.external_services.payment_provider = payment_config.get(
                "provider", "razorpay"
            )
            self.external_services.payment_sandbox = payment_config.get(
                "sandbox_mode", False
            )

        # Storage configuration
        if "storage" in config:
            storage_config = config["storage"]
            self.external_services.storage_provider = storage_config.get(
                "provider", "local"
            )

    @property
    def is_development(self) -> bool:
        """Check if running in development mode"""
        return self.environment.lower() == "development"

    @property
    def is_production(self) -> bool:
        """Check if running in production mode"""
        return self.environment.lower() == "production"


@lru_cache()
def get_settings() -> AppSettings:
    """Get cached application settings instance"""
    return AppSettings()


# Export settings instance and classes
settings = get_settings()

__all__ = [
    "AppSettings",
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
    "get_settings",
    "settings",
]
