"""
Permission checking utilities.

Resolves the required permission from an HTTP request and checks it against
the user's role permissions + any custom overrides.
"""

from starlette.requests import Request


# ── Map URL path segments to module names ────────────────────────
MODULE_MAP: dict[str, str] = {
    "users": "users",
    "customers": "customers",
    "products": "products",
    "items": "products",        # /api/v1/items → products:* permission
    "stores": "stores",
    "pos": "pos",
    "inventory": "inventory",
    "vendors": "vendors",
    "invoices": "invoices",
    "reports": "reports",
}

# ── Map HTTP methods to RBAC actions ─────────────────────────────
METHOD_TO_ACTION: dict[str, str] = {
    "GET": "read",
    "POST": "create",
    "PUT": "update",
    "PATCH": "update",
    "DELETE": "delete",
}


def resolve_permission_from_request(request: Request) -> str | None:
    """
    Derive the required permission string from the request.

    URL pattern expected:  /api/{version}/{module}/...
    Returns e.g. "users:read" or None if module is unknown.
    """
    path_parts = request.url.path.strip("/").split("/")
    # path_parts = ["api", "v1", "users", ...]
    module_name = path_parts[2] if len(path_parts) > 2 else None
    module = MODULE_MAP.get(module_name) if module_name else None
    action = METHOD_TO_ACTION.get(request.method)

    if not module or not action:
        return None

    return f"{module}:{action}"


def check_permission(
    user_permissions: list[str],
    required: str,
) -> bool:
    """
    Check if the user's permission list satisfies the required permission.

    Supports wildcards:
      - "*:*"     → full access
      - "users:*" → all actions on users module
      - "users:read" → exact match
    """
    if not required:
        return False

    req_module, req_action = required.split(":")

    for perm in user_permissions:
        p_module, p_action = perm.split(":")

        # global wildcard
        if p_module == "*" and p_action == "*":
            return True

        # module wildcard  (e.g. "users:*")
        if p_module == req_module and p_action == "*":
            return True

        # exact match
        if p_module == req_module and p_action == req_action:
            return True

    return False
