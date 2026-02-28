"""
Tenant collection resolver.

Convention:
  - Tenant-scoped collections:  {org_slug}_{collection_name}
    e.g.  lhs_users, lhs_customers, lhs_products
  - Global collections:         {collection_name}
    e.g.  organizations  (shared across all tenants)
"""

import re
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorCollection


_SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9\-]*$")


def _validate_slug(org_slug: str) -> str:
    """Ensure the slug is safe for use as a collection name prefix."""
    slug = org_slug.strip().lower()
    if not _SLUG_PATTERN.match(slug):
        raise ValueError(
            f"Invalid org_slug '{org_slug}'. "
            "Must be lowercase alphanumeric with optional hyphens."
        )
    # MongoDB collection names cannot contain hyphens in all drivers,
    # so replace hyphens with underscores for the collection name.
    return slug.replace("-", "_")


def get_tenant_collection(
    db: AsyncIOMotorDatabase,
    org_slug: str,
    collection_name: str,
) -> AsyncIOMotorCollection:
    """
    Return a tenant-scoped collection.

    Example:
        get_tenant_collection(db, "lhs", "users")  →  db["lhs_users"]
    """
    safe_slug = _validate_slug(org_slug)
    return db[f"{safe_slug}_{collection_name}"]


def get_global_collection(
    db: AsyncIOMotorDatabase,
    collection_name: str,
) -> AsyncIOMotorCollection:
    """
    Return a global (non-tenant) collection.

    Example:
        get_global_collection(db, "organizations")  →  db["organizations"]
    """
    return db[collection_name]
