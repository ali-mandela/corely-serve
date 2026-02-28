from pydantic_settings import BaseSettings
from typing import Optional


class CorelySettings(BaseSettings):
    """Core application settings"""

    # Application
    app_name: str = "Corely Enterprise System"
    debug: bool = False
    version: str = "1.0.0"

    mongodb_atlas_uri: Optional[str] = None
    database_name: str = "corely_db"

    # Security
    secret_key: str = (
        "your-secret-key-change-in-productionlaskdnjkajbfdasbdkbaksdasbdoidjsbanda"
    )
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 300
    app_key: str = "corely@shm"

    # CORS
    allowed_origins: list = ["*"]
    allowed_methods: list = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
    allowed_headers: list = ["*"]

    # SMTP Settings
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: Optional[bool] = None
    smtp_from_email: Optional[str] = None

    # Additional settings
    frontend_url: Optional[str] = None
    db_host: Optional[str] = None
    db_name: Optional[str] = None
    db_user: Optional[str] = None
    db_pass: Optional[str] = None
    cache_enabled: Optional[bool] = False
    redis_enabled: Optional[bool] = False
    rate_limit_enabled: Optional[bool] = True
    environment: str = "development"
    rate_limit_requests_per_minute: Optional[int] = 60
    rate_limit_requests_per_hour: Optional[int] = 1000
    security_require_https: Optional[bool] = False
    security_csp_enabled: Optional[bool] = False
    security_hsts_max_age: Optional[int] = 31536000
    db_max_connections: Optional[int] = 10
    db_min_connections: Optional[int] = 2
    db_connection_timeout: Optional[int] = 30
    db_query_timeout: Optional[int] = 60
    db_health_check_interval: Optional[int] = 30
    db_max_reconnect_attempts: Optional[int] = 5
    app_version: Optional[str] = "1.0.0"
    api_version: Optional[str] = "v1"
    corely: Optional[str] = None  # JSON string
    # ✅ Default CORS configuration

    cors_allowed_origins: list[str] = [
        "http://localhost:4200",
        "http://localhost:60351",
        "http://127.0.0.1:4200",
    ]
    cors_allow_credentials: bool = True
    cors_allowed_methods: list[str] = ["*"]  # Allow all HTTP methods
    cors_allowed_headers: list[str] = ["*"]  # Allow all headers

    @property
    def effective_mongodb_uri(self) -> str:
        """Return the effective MongoDB URI to use"""
        return self.mongodb_atlas_uri

    class Config:
        env_file = ".env"
        extra = "ignore"  # Ignore extra fields
