"""
Role definitions and permission matrix.

Permission format:  "{module}:{action}"
  - Modules : users, customers, products, stores, pos, inventory, reports
  - Actions : read, create, update, delete, *  (wildcard)
  - Wildcard: "*:*"  means ALL modules, ALL actions
"""

ROLES: dict[str, list[str]] = {
    "super_admin": [
        "*:*",  # everything
    ],
    "admin": [
        "users:*",
        "customers:*",
        "products:*",
        "stores:*",
        "pos:*",
        "inventory:*",
        "reports:*",
    ],
    "manager": [
        "users:read",
        "customers:*",
        "products:*",
        "stores:read",
        "pos:*",
        "inventory:read",
        "reports:read",
    ],
    "employee": [
        "customers:read",
        "products:read",
        "pos:create",
        "pos:read",
    ],
}


def get_role_permissions(role: str) -> list[str]:
    """Return the permission list for a given role name."""
    return ROLES.get(role, [])
