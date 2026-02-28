from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from .env file."""

    # ── Application ──────────────────────────────────────────────
    app_name: str = "Corely Enterprise System"
    app_version: str = "1.0.0"
    debug: bool = False
    environment: str = "development"
    api_version: str = "v1"

    # ── Database ─────────────────────────────────────────────────
    mongodb_atlas_uri: Optional[str] = None
    database_name: str = "corely_db"

    # ── JWT / Security ───────────────────────────────────────────
    secret_key: str = "change-me-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 1440  # 24 hours

    # ── Platform key (for org setup endpoint) ────────────────────
    app_key: str = "corely_application"

    # ── CORS ─────────────────────────────────────────────────────
    cors_allowed_origins: list[str] = [
        "http://localhost:4200",
        "http://localhost:3000",
        "http://127.0.0.1:4200",
    ]
    cors_allow_credentials: bool = True
    cors_allowed_methods: list[str] = ["*"]
    cors_allowed_headers: list[str] = ["*"]

    # ── SMTP (optional) ─────────────────────────────────────────
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: Optional[bool] = None
    smtp_from_email: Optional[str] = None
    frontend_url: Optional[str] = None

    class Config:
        env_file = ".env.local"
        extra = "ignore"


# ── Module-level singleton ──────────────────────────────────────
settings = Settings()
