"""
Enterprise Multi-Tenant Stores Management System - Environment Configuration
This module handles environment-specific configurations for Development and Production only.
"""

import os
import sys
from enum import Enum
from typing import Dict, Any, Optional, List
from pathlib import Path

from app._core.utils.constants import EnvironmentConstants


class Environment(Enum):
    """Application environment types - Development and Production only"""

    DEVELOPMENT = "development"
    PRODUCTION = "production"


class EnvironmentConfig:
    """Environment configuration manager for enterprise stores management system"""

    def __init__(self):
        self._current_env = None
        self._config_cache = {}
        self._load_environment()

    def _load_environment(self):
        """Load and validate current environment"""
        env_name = os.getenv("ENVIRONMENT", "development").lower()

        try:
            self._current_env = Environment(env_name)
        except ValueError:
            print(
                f"⚠️ Warning: Unknown environment '{env_name}', defaulting to development"
            )
            self._current_env = Environment.DEVELOPMENT

    @property
    def current(self) -> Environment:
        """Get current environment"""
        return self._current_env

    @property
    def name(self) -> str:
        """Get current environment name"""
        return self._current_env.value

    def is_development(self) -> bool:
        """Check if running in development environment"""
        return self._current_env == Environment.DEVELOPMENT

    def is_production(self) -> bool:
        """Check if running in production environment"""
        return self._current_env == Environment.PRODUCTION

    def is_local(self) -> bool:
        """Check if running in local environment (development)"""
        return self._current_env == Environment.DEVELOPMENT

    def is_deployed(self) -> bool:
        """Check if running in deployed environment (production)"""
        return self._current_env == Environment.PRODUCTION


class DatabaseEnvironmentConfig:
    """Database configuration per environment"""

    @staticmethod
    def get_config(env: Environment) -> Dict[str, Any]:
        """Get database configuration for environment"""
        base_config = {
            "max_connections": 20,
            "min_connections": 5,
            "connection_timeout": 30,
            "query_timeout": 60,
            "retry_attempts": 3,
            "retry_delay": 1,
            "enable_ssl": False,
            "enable_replication": False,
        }

        if env == Environment.DEVELOPMENT:
            return {
                **base_config,
                "host": os.getenv("DEV_DB_HOST", "localhost"),
                "port": int(os.getenv("DEV_DB_PORT", "27017")),
                "database": os.getenv("DEV_DB_NAME", "stores_dev"),
                "username": os.getenv("DEV_DB_USER", ""),
                "password": os.getenv("DEV_DB_PASS", ""),
                "max_connections": 10,
                "enable_query_logging": True,
                "slow_query_threshold": 1.0,  # Log queries > 1 second
                "enable_profiling": True,
                "log_level": "DEBUG",
            }

        elif env == Environment.PRODUCTION:
            return {
                **base_config,
                "host": os.getenv("PROD_DB_HOST"),
                "port": int(os.getenv("PROD_DB_PORT", "27017")),
                "database": os.getenv("PROD_DB_NAME", "stores_production"),
                "username": os.getenv("PROD_DB_USER"),
                "password": os.getenv("PROD_DB_PASS"),
                "max_connections": 100,
                "min_connections": 20,
                "enable_ssl": True,
                "enable_replication": True,
                "replica_set": os.getenv("PROD_DB_REPLICA_SET", "rs0"),
                "read_preference": "secondaryPreferred",
                "write_concern": {"w": "majority", "wtimeout": 5000},
                "read_concern": {"level": "majority"},
                "enable_query_logging": False,
                "log_level": "ERROR",
                "connection_pool_settings": {
                    "maxPoolSize": 100,
                    "minPoolSize": 20,
                    "maxIdleTimeMS": 300000,  # 5 minutes
                    "waitQueueTimeoutMS": 30000,  # 30 seconds
                },
            }


class RedisEnvironmentConfig:
    """Redis configuration per environment"""

    @staticmethod
    def get_config(env: Environment) -> Dict[str, Any]:
        """Get Redis configuration for environment"""
        base_config = {
            "socket_timeout": 5,
            "socket_connect_timeout": 5,
            "retry_on_timeout": True,
            "health_check_interval": 30,
            "max_connections": 50,
        }

        if env == Environment.DEVELOPMENT:
            return {
                **base_config,
                "host": os.getenv("DEV_REDIS_HOST", "localhost"),
                "port": int(os.getenv("DEV_REDIS_PORT", "6379")),
                "db": int(os.getenv("DEV_REDIS_DB", "0")),
                "password": os.getenv("DEV_REDIS_PASS"),
                "max_connections": 10,
                "decode_responses": True,
                "enable_debug": True,
            }

        elif env == Environment.PRODUCTION:
            return {
                **base_config,
                "host": os.getenv("PROD_REDIS_HOST"),
                "port": int(os.getenv("PROD_REDIS_PORT", "6379")),
                "db": int(os.getenv("PROD_REDIS_DB", "0")),
                "password": os.getenv("PROD_REDIS_PASS"),
                "ssl": True,
                "ssl_cert_reqs": "required",
                "max_connections": 100,
                "decode_responses": True,
                "sentinel": {
                    "enabled": os.getenv("PROD_REDIS_SENTINEL_ENABLED", "false").lower()
                    == "true",
                    "hosts": (
                        os.getenv("PROD_REDIS_SENTINEL_HOSTS", "").split(",")
                        if os.getenv("PROD_REDIS_SENTINEL_HOSTS")
                        else []
                    ),
                    "service_name": os.getenv(
                        "PROD_REDIS_SENTINEL_SERVICE", "mymaster"
                    ),
                },
                "cluster": {
                    "enabled": os.getenv("PROD_REDIS_CLUSTER_ENABLED", "false").lower()
                    == "true",
                    "nodes": (
                        os.getenv("PROD_REDIS_CLUSTER_NODES", "").split(",")
                        if os.getenv("PROD_REDIS_CLUSTER_NODES")
                        else []
                    ),
                },
            }


class SecurityEnvironmentConfig:
    """Security configuration per environment"""

    @staticmethod
    def get_config(env: Environment) -> Dict[str, Any]:
        """Get security configuration for environment"""
        base_config = {
            "session_expire_hours": 8,
            "max_sessions_per_user": 3,
            "password_min_length": 12,
            "require_mfa": False,
            "allowed_origins": [],
            "rate_limiting_enabled": True,
        }

        if env == Environment.DEVELOPMENT:
            return {
                **base_config,
                "secret_key": os.getenv(
                    "DEV_SECRET_KEY", "dev-secret-key-change-me-for-production"
                ),
                "jwt_secret": os.getenv("DEV_JWT_SECRET", "dev-jwt-secret-change-me"),
                "allowed_origins": [
                    "http://localhost:3000",
                    "http://localhost:3001",
                    "http://localhost:8000",
                    "http://127.0.0.1:3000",
                    "http://127.0.0.1:3001",
                    "http://127.0.0.1:8000",
                ],
                "cors_allow_credentials": True,
                "require_https": False,
                "password_min_length": 8,  # Relaxed for development
                "session_expire_hours": 24,  # Longer sessions for dev
                "max_sessions_per_user": 10,  # More sessions for dev
                "rate_limiting_enabled": False,  # Disabled for dev convenience
                "csrf_protection": False,  # Disabled for dev
                "debug_toolbar": True,
                "allow_test_users": True,
                "encryption_key": os.getenv("DEV_ENCRYPTION_KEY", "dev-encryption-key"),
            }

        elif env == Environment.PRODUCTION:
            return {
                **base_config,
                "secret_key": os.getenv("PROD_SECRET_KEY"),
                "jwt_secret": os.getenv("PROD_JWT_SECRET"),
                "allowed_origins": [
                    os.getenv("PROD_FRONTEND_URL", "https://app.yourdomain.com"),
                    os.getenv("PROD_ADMIN_URL", "https://admin.yourdomain.com"),
                    os.getenv("PROD_MOBILE_URL", "https://mobile.yourdomain.com"),
                ],
                "cors_allow_credentials": True,
                "require_https": True,
                "require_mfa": True,  # Mandatory for production
                "max_login_attempts": 3,
                "lockout_duration_minutes": 30,
                "session_expire_hours": 4,  # Shorter sessions for security
                "require_password_change_days": 90,
                "csrf_protection": True,
                "debug_toolbar": False,
                "allow_test_users": False,
                "encryption_key": os.getenv("PROD_ENCRYPTION_KEY"),
                "security_headers": {
                    "hsts_max_age": 31536000,  # 1 year
                    "content_security_policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
                    "x_frame_options": "DENY",
                    "x_content_type_options": "nosniff",
                    "referrer_policy": "strict-origin-when-cross-origin",
                },
            }


class LoggingEnvironmentConfig:
    """Logging configuration per environment"""

    @staticmethod
    def get_config(env: Environment) -> Dict[str, Any]:
        """Get logging configuration for environment"""
        base_config = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "detailed": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s",
                    "datefmt": "%Y-%m-%d %H:%M:%S",
                },
                "simple": {"format": "%(levelname)s - %(message)s"},
                "json": {
                    "format": '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "module": "%(module)s", "function": "%(funcName)s", "line": %(lineno)d, "message": "%(message)s"}',
                    "datefmt": "%Y-%m-%dT%H:%M:%S",
                },
            },
        }

        if env == Environment.DEVELOPMENT:
            return {
                **base_config,
                "handlers": {
                    "console": {
                        "class": "logging.StreamHandler",
                        "level": "DEBUG",
                        "formatter": "detailed",
                        "stream": "ext://sys.stdout",
                    },
                    "file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "level": "DEBUG",
                        "formatter": "detailed",
                        "filename": "logs/development.log",
                        "maxBytes": 10485760,  # 10MB
                        "backupCount": 5,
                    },
                    "error_file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "level": "ERROR",
                        "formatter": "detailed",
                        "filename": "logs/errors.log",
                        "maxBytes": 10485760,  # 10MB
                        "backupCount": 3,
                    },
                },
                "root": {
                    "level": "DEBUG",
                    "handlers": ["console", "file", "error_file"],
                },
                "loggers": {
                    "uvicorn": {
                        "level": "INFO",
                        "handlers": ["console"],
                        "propagate": False,
                    },
                    "fastapi": {
                        "level": "DEBUG",
                        "handlers": ["console", "file"],
                        "propagate": False,
                    },
                    "core": {
                        "level": "DEBUG",
                        "handlers": ["console", "file"],
                        "propagate": False,
                    },
                },
            }

        elif env == Environment.PRODUCTION:
            return {
                **base_config,
                "handlers": {
                    "console": {
                        "class": "logging.StreamHandler",
                        "level": "WARNING",
                        "formatter": "json",
                        "stream": "ext://sys.stdout",
                    },
                    "file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "level": "INFO",
                        "formatter": "json",
                        "filename": "/var/log/stores-management/application.log",
                        "maxBytes": 104857600,  # 100MB
                        "backupCount": 20,
                    },
                    "error_file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "level": "ERROR",
                        "formatter": "json",
                        "filename": "/var/log/stores-management/errors.log",
                        "maxBytes": 52428800,  # 50MB
                        "backupCount": 20,
                    },
                    "audit_file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "level": "INFO",
                        "formatter": "json",
                        "filename": "/var/log/stores-management/audit.log",
                        "maxBytes": 52428800,  # 50MB
                        "backupCount": 30,
                    },
                },
                "root": {
                    "level": "INFO",
                    "handlers": ["console", "file", "error_file"],
                },
                "loggers": {
                    "audit": {
                        "level": "INFO",
                        "handlers": ["audit_file"],
                        "propagate": False,
                    },
                    "security": {
                        "level": "WARNING",
                        "handlers": ["console", "error_file"],
                        "propagate": False,
                    },
                },
            }


class APIEnvironmentConfig:
    """API configuration per environment"""

    @staticmethod
    def get_config(env: Environment) -> Dict[str, Any]:
        """Get API configuration for environment"""
        base_config = {
            "title": "Enterprise Stores Management API",
            "description": "Multi-Tenant Stores Management System for India",
            "version": "1.0.0",
            "contact": {"name": "API Support", "email": "api-support@yourdomain.com"},
            "license_info": {
                "name": "Proprietary",
                "url": "https://yourdomain.com/license",
            },
        }

        if env == Environment.DEVELOPMENT:
            return {
                **base_config,
                "debug": True,
                "reload": True,
                "host": "0.0.0.0",
                "port": int(os.getenv("DEV_PORT", "8000")),
                "workers": 1,
                "docs_url": "/docs",
                "redoc_url": "/redoc",
                "openapi_url": "/openapi.json",
                "include_admin_routes": True,
                "include_debug_routes": True,
                "include_metrics": True,
                "swagger_ui_parameters": {
                    "deepLinking": True,
                    "displayRequestDuration": True,
                    "docExpansion": "none",
                    "filter": True,
                    "showExtensions": True,
                    "showCommonExtensions": True,
                },
            }

        elif env == Environment.PRODUCTION:
            return {
                **base_config,
                "debug": False,
                "host": "0.0.0.0",
                "port": int(os.getenv("PROD_PORT", "8000")),
                "workers": int(os.getenv("PROD_WORKERS", "8")),
                "docs_url": None,  # Disable docs in production
                "redoc_url": None,
                "openapi_url": None,
                "include_admin_routes": False,
                "include_debug_routes": False,
                "include_metrics": True,
                "access_log": True,
                "proxy_headers": True,
                "forwarded_allow_ips": "*",
                "keep_alive": 65,
                "max_requests": 1000,
                "max_requests_jitter": 100,
                "preload_app": True,
            }


class ExternalServicesConfig:
    """External services configuration per environment"""

    @staticmethod
    def get_config(env: Environment) -> Dict[str, Any]:
        """Get external services configuration for environment"""
        base_config = {
            "email": {
                "enabled": True,
                "timeout": 30,
                "retry_attempts": 3,
            },
            "sms": {
                "enabled": True,
                "timeout": 10,
                "retry_attempts": 2,
            },
            "payment": {
                "enabled": True,
                "timeout": 60,
                "retry_attempts": 3,
            },
            "storage": {
                "enabled": True,
                "timeout": 120,
            },
            "gst": {
                "enabled": True,
                "timeout": 30,
                "api_version": "v1",
            },
        }

        if env == Environment.DEVELOPMENT:
            return {
                **base_config,
                "email": {
                    **base_config["email"],
                    "provider": "console",  # Print to console in dev
                    "from_email": "dev@localhost",
                    "from_name": "Dev Stores Management",
                },
                "sms": {
                    **base_config["sms"],
                    "provider": "console",  # Print to console in dev
                    "from_name": "Dev SMS",
                },
                "payment": {
                    **base_config["payment"],
                    "provider": "razorpay",
                    "sandbox_mode": True,
                    "razorpay_key": os.getenv("DEV_RAZORPAY_KEY", "rzp_test_"),
                    "razorpay_secret": os.getenv("DEV_RAZORPAY_SECRET"),
                    "webhook_secret": os.getenv("DEV_RAZORPAY_WEBHOOK_SECRET"),
                    "currency": "INR",
                },
                "storage": {
                    **base_config["storage"],
                    "provider": "local",
                    "local_path": "uploads/",
                    "max_file_size": 10 * 1024 * 1024,  # 10MB
                    "allowed_extensions": [
                        ".jpg",
                        ".jpeg",
                        ".png",
                        ".pdf",
                        ".xlsx",
                        ".csv",
                    ],
                },
                "gst": {
                    **base_config["gst"],
                    "provider": "mock",  # Mock GST API in dev
                    "base_url": "https://api.sandbox.gst.gov.in",
                },
                "maps": {
                    "provider": "google",
                    "api_key": os.getenv("DEV_GOOGLE_MAPS_KEY"),
                    "enabled": True,
                },
            }

        elif env == Environment.PRODUCTION:
            return {
                **base_config,
                "email": {
                    **base_config["email"],
                    "provider": "smtp",
                    "smtp_host": os.getenv("PROD_SMTP_HOST"),
                    "smtp_port": int(os.getenv("PROD_SMTP_PORT", "587")),
                    "smtp_user": os.getenv("PROD_SMTP_USER"),
                    "smtp_password": os.getenv("PROD_SMTP_PASSWORD"),
                    "use_tls": True,
                    "from_email": os.getenv("PROD_FROM_EMAIL"),
                    "from_name": "Stores Management",
                    "bounce_handling": True,
                },
                "sms": {
                    **base_config["sms"],
                    "provider": "msg91",  # Indian SMS provider
                    "api_key": os.getenv("PROD_MSG91_API_KEY"),
                    "route": "4",  # Transactional route
                    "sender_id": os.getenv("PROD_SMS_SENDER_ID", "STORES"),
                    "template_verification": True,
                },
                "payment": {
                    **base_config["payment"],
                    "provider": "razorpay",
                    "sandbox_mode": False,
                    "razorpay_key": os.getenv("PROD_RAZORPAY_KEY"),
                    "razorpay_secret": os.getenv("PROD_RAZORPAY_SECRET"),
                    "webhook_secret": os.getenv("PROD_RAZORPAY_WEBHOOK_SECRET"),
                    "currency": "INR",
                    "auto_capture": True,
                    "payment_methods": ["card", "netbanking", "wallet", "upi"],
                },
                "storage": {
                    **base_config["storage"],
                    "provider": "aws_s3",
                    "aws_access_key": os.getenv("PROD_AWS_ACCESS_KEY"),
                    "aws_secret_key": os.getenv("PROD_AWS_SECRET_KEY"),
                    "aws_region": os.getenv(
                        "PROD_AWS_REGION", "ap-south-1"
                    ),  # Mumbai region
                    "bucket_name": os.getenv("PROD_S3_BUCKET"),
                    "cdn_url": os.getenv("PROD_CDN_URL"),
                    "max_file_size": 50 * 1024 * 1024,  # 50MB
                    "allowed_extensions": [
                        ".jpg",
                        ".jpeg",
                        ".png",
                        ".pdf",
                        ".xlsx",
                        ".csv",
                        ".docx",
                    ],
                },
                "gst": {
                    **base_config["gst"],
                    "provider": "government",
                    "base_url": "https://api.gst.gov.in",
                    "api_key": os.getenv("PROD_GST_API_KEY"),
                    "client_id": os.getenv("PROD_GST_CLIENT_ID"),
                    "client_secret": os.getenv("PROD_GST_CLIENT_SECRET"),
                },
                "maps": {
                    "provider": "google",
                    "api_key": os.getenv("PROD_GOOGLE_MAPS_KEY"),
                    "enabled": True,
                    "places_api": True,
                    "geocoding_api": True,
                },
            }


class MonitoringConfig:
    """Monitoring and metrics configuration per environment"""

    @staticmethod
    def get_config(env: Environment) -> Dict[str, Any]:
        """Get monitoring configuration for environment"""
        if env == Environment.DEVELOPMENT:
            return {
                "enabled": True,
                "metrics_enabled": True,
                "health_check_enabled": True,
                "prometheus_enabled": False,
                "newrelic_enabled": False,
                "sentry_enabled": False,
                "custom_metrics": True,
                "performance_monitoring": True,
            }

        elif env == Environment.PRODUCTION:
            return {
                "enabled": True,
                "metrics_enabled": True,
                "health_check_enabled": True,
                "prometheus_enabled": True,
                "prometheus_port": int(os.getenv("PROMETHEUS_PORT", "9090")),
                "newrelic_enabled": True,
                "newrelic_license_key": os.getenv("NEWRELIC_LICENSE_KEY"),
                "sentry_enabled": True,
                "sentry_dsn": os.getenv("SENTRY_DSN"),
                "sentry_environment": "production",
                "custom_metrics": True,
                "performance_monitoring": True,
                "error_tracking": True,
                "uptime_monitoring": True,
            }


# Global environment instance
env_config = EnvironmentConfig()


def get_environment_config() -> EnvironmentConfig:
    """Get the global environment configuration instance"""
    return env_config


def get_current_environment() -> Environment:
    """Get the current environment"""
    return env_config.current


def is_development() -> bool:
    """Check if running in development"""
    return env_config.is_development()


def is_production() -> bool:
    """Check if running in production"""
    return env_config.is_production()


# Export all configuration classes and functions
__all__ = [
    "Environment",
    "EnvironmentConfig",
    "DatabaseEnvironmentConfig",
    "RedisEnvironmentConfig",
    "SecurityEnvironmentConfig",
    "LoggingEnvironmentConfig",
    "APIEnvironmentConfig",
    "ExternalServicesConfig",
    "MonitoringConfig",
    "get_environment_config",
    "get_current_environment",
    "is_development",
    "is_production",
]
