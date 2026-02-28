from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime, time
import re
from fastapi import Request
from .models import ABACContext, AttributeType


class AttributeProvider(ABC):
    """Abstract base class for attribute providers"""

    @abstractmethod
    async def get_attributes(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get attributes from this provider"""
        pass


class SubjectAttributeProvider(AttributeProvider):
    """Provides subject (user) attributes"""

    async def get_attributes(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get subject attributes from user context"""
        user = context.get("user")
        if not user:
            return {}

        # Extract user attributes - adjust based on your user model
        attributes = {
            "user_id": user.get("id") or user.get("user_id"),
            "username": user.get("username"),
            "email": user.get("email"),
            "roles": user.get("roles", []),
            "permissions": user.get("permissions", []),
            "department": user.get("department"),
            "organization_id": user.get("organization_id"),
            "is_admin": user.get("is_admin", False),
            "is_active": user.get("is_active", True),
            "created_at": user.get("created_at"),
            "last_login": user.get("last_login"),
        }

        # Remove None values
        return {k: v for k, v in attributes.items() if v is not None}


class ResourceAttributeProvider(AttributeProvider):
    """Provides resource attributes"""

    async def get_attributes(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get resource attributes from request context"""
        resource = context.get("resource", {})
        request = context.get("request")

        attributes = {}

        # From explicit resource context
        if resource:
            attributes.update({
                "resource_id": resource.get("id"),
                "resource_type": resource.get("type"),
                "resource_owner": resource.get("owner"),
                "resource_sensitivity": resource.get("sensitivity", "public"),
                "resource_department": resource.get("department"),
                "resource_organization": resource.get("organization_id"),
                "created_at": resource.get("created_at"),
                "status": resource.get("status"),
            })

        # From request path and parameters
        if request:
            path = request.url.path
            path_params = getattr(request, "path_params", {})

            # Extract resource information from URL
            attributes.update({
                "endpoint": path,
                "resource_path": path,
                **{f"path_{k}": v for k, v in path_params.items()}
            })

        # Remove None values
        return {k: v for k, v in attributes.items() if v is not None}


class ActionAttributeProvider(AttributeProvider):
    """Provides action attributes"""

    async def get_attributes(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get action attributes from request"""
        request = context.get("request")
        if not request:
            return {}

        method = request.method.lower()
        path = request.url.path

        # Map HTTP methods to CRUD operations
        crud_mapping = {
            "get": "read",
            "post": "create",
            "put": "update",
            "patch": "update",
            "delete": "delete"
        }

        attributes = {
            "method": method,
            "action": crud_mapping.get(method, method),
            "endpoint": path,
            "is_read_operation": method == "get",
            "is_write_operation": method in ["post", "put", "patch", "delete"],
            "is_modification": method in ["put", "patch", "delete"],
        }

        # Add specific action based on endpoint patterns
        if "/admin" in path:
            attributes["is_admin_action"] = True
        if "/api/v1/users" in path:
            attributes["target_entity"] = "user"
        if "/api/v1/organizations" in path:
            attributes["target_entity"] = "organization"

        return attributes


class EnvironmentAttributeProvider(AttributeProvider):
    """Provides environment attributes"""

    def __init__(self):
        self.business_hours_start = time(9, 0)  # 9 AM
        self.business_hours_end = time(17, 0)   # 5 PM

    async def get_attributes(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get environment attributes"""
        request = context.get("request")
        now = datetime.utcnow()

        attributes = {
            "timestamp": now.isoformat(),
            "hour": now.hour,
            "day_of_week": now.strftime("%A").lower(),
            "day_of_month": now.day,
            "month": now.month,
            "year": now.year,
            "is_weekend": now.weekday() >= 5,  # Saturday = 5, Sunday = 6
            "is_business_hours": self._is_business_hours(now.time()),
        }

        if request:
            # Client information
            client_host = getattr(request.client, "host", None) if request.client else None
            attributes.update({
                "ip_address": client_host,
                "user_agent": request.headers.get("user-agent"),
                "origin": request.headers.get("origin"),
                "referer": request.headers.get("referer"),
                "content_type": request.headers.get("content-type"),
                "accept": request.headers.get("accept"),
            })

            # Request characteristics
            attributes.update({
                "has_body": request.method in ["POST", "PUT", "PATCH"],
                "is_api_request": "/api/" in request.url.path,
                "protocol": request.url.scheme,
                "host": request.url.hostname,
            })

        # Remove None values
        return {k: v for k, v in attributes.items() if v is not None}

    def _is_business_hours(self, current_time: time) -> bool:
        """Check if current time is within business hours"""
        return self.business_hours_start <= current_time <= self.business_hours_end


class AttributeManager:
    """Manages all attribute providers and provides unified interface"""

    def __init__(self):
        self.providers = {
            AttributeType.SUBJECT: SubjectAttributeProvider(),
            AttributeType.RESOURCE: ResourceAttributeProvider(),
            AttributeType.ACTION: ActionAttributeProvider(),
            AttributeType.ENVIRONMENT: EnvironmentAttributeProvider(),
        }

    async def get_all_attributes(self, context: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Get attributes from all providers"""
        attributes = {}

        for attr_type, provider in self.providers.items():
            try:
                provider_attributes = await provider.get_attributes(context)
                attributes[attr_type.value] = provider_attributes
            except Exception as e:
                # Log error but continue with other providers
                print(f"Error getting {attr_type.value} attributes: {e}")
                attributes[attr_type.value] = {}

        return attributes

    async def build_abac_context(self,
                                user: Optional[Dict[str, Any]] = None,
                                resource: Optional[Dict[str, Any]] = None,
                                request: Optional[Request] = None) -> ABACContext:
        """Build ABAC context from various sources"""

        context = {
            "user": user,
            "resource": resource,
            "request": request
        }

        # Get all attributes
        all_attributes = await self.get_all_attributes(context)

        subject_attrs = all_attributes.get("subject", {})
        resource_attrs = all_attributes.get("resource", {})
        action_attrs = all_attributes.get("action", {})
        env_attrs = all_attributes.get("environment", {})

        # Build ABACContext
        return ABACContext(
            # Subject attributes
            subject_id=subject_attrs.get("user_id"),
            user_id=subject_attrs.get("user_id"),
            roles=subject_attrs.get("roles", []),
            permissions=subject_attrs.get("permissions", []),
            department=subject_attrs.get("department"),
            organization_id=subject_attrs.get("organization_id"),

            # Resource attributes
            resource_type=resource_attrs.get("resource_type"),
            resource_id=resource_attrs.get("resource_id"),
            resource_owner=resource_attrs.get("resource_owner"),
            resource_sensitivity=resource_attrs.get("resource_sensitivity"),

            # Action attributes
            action=action_attrs.get("action"),
            method=action_attrs.get("method"),

            # Environment attributes
            ip_address=env_attrs.get("ip_address"),
            user_agent=env_attrs.get("user_agent"),
            time_of_day=str(env_attrs.get("hour", 0)),
            day_of_week=env_attrs.get("day_of_week"),
            is_weekend=env_attrs.get("is_weekend", False),
            is_business_hours=env_attrs.get("is_business_hours", True),
            location=env_attrs.get("location")
        )