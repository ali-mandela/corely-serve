from fastapi import APIRouter, Depends, HTTPException, status, Header
from typing import Annotated
from jose import JWTError, jwt
from app._models.info import InfoModel as Info, AppAdminSecrets
from app._services.info_service import InfoService, get_info_service
from app.utils.exceptions import AuthenticationError, DuplicateError, NotFoundError
from app._core.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    verify_token,
)
from app._core.config import settings

global_config = APIRouter()


async def verify_app_admin_token(authorization: Annotated[str, Header()]) -> bool:
    """
    Verify that the token belongs to an app_admin with corely org_id
    Expected header: Authorization: Bearer <token>
    """
    try:
        # Extract token from Authorization header
        if not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization header format. Use 'Bearer <token>'",
            )

        token = authorization.split(" ")[1]

        # Decode JWT token
        try:
            payload = jwt.decode(
                token, settings.secret_key, algorithms=[settings.algorithm]
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired"
            )

        # Extract user info from token
        user_role = payload.get("role")
        user_org_id = payload.get("org_id")

        # Verify role is app_admin
        if user_role != "app_admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role: app_admin, but got: {user_role}",
            )

        # Verify org_id is corely
        if user_org_id != "corely":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required org_id: corely, but got: {user_org_id}",
            )

        # Return user info if validation passes
        return True

    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Handle any other unexpected errors
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token validation failed: {str(e)}",
        )


@global_config.post("/create-organisation", status_code=status.HTTP_201_CREATED)
async def create_org_with_admin(
    info_data: Info,
    info_service: InfoService = Depends(get_info_service),
    admin_user: dict = Depends(verify_app_admin_token),
):
    """
    Create organization with admin user.

    Requires:
    - Authorization header with Bearer token
    - Token must have role: app_admin
    - Token must have org_id: corely

    Headers:
        Authorization: Bearer <your-jwt-token>
    """
    try:
        if admin_user is not True:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. Invalid app admin token.",
            )
        return await info_service.create_org_with_admin(info_data)
    except DuplicateError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


@global_config.post("/app-admin", status_code=status.HTTP_200_OK)
async def create_app_admin(
    admin_data: AppAdminSecrets, info_service: InfoService = Depends(get_info_service)
):
    """
    Verify app admin secrets and potentially create/authenticate app admin.
    This route doesn't require token authentication as it's used to obtain tokens.
    """
    try:
        return info_service.verify_app_admin_secrets(admin_data)
    except DuplicateError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except AuthenticationError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )
