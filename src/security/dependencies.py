# src/auth/dependencies.py
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from src.services.user_service import UserService
from src.security.jwt_manager import decode_token
from src.config.logger import Logger
from src.config.database import get_db
from typing import AsyncGenerator

log = Logger().get_logger()

# OAuth2 password bearer token (Swagger login endpoint)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# ----------------------------
# UserService dependency factory
# ----------------------------
async def get_db_user_service() -> AsyncGenerator[UserService, None]:
    """
    Factory dependency to create UserService with DB session.
    FastAPI will handle cleanup after the request.
    """
    async for db in get_db():  # iterate over the generator
        log.debug(f"[Dependency] Created UserService with db session {db}")
        yield UserService(db)


# ----------------------------
# Current user dependency
# ----------------------------
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    user_service: UserService = Depends(get_db_user_service)
):
    """
    Fetch and validate the current user from the JWT access token.
    Raises HTTPException if token is invalid or user does not exist.
    """
    try:
        log.info(f"[Auth] Verifying token: {token[:10]}...")  # partial token for privacy
        payload = await decode_token(token)
        log.warning(f"payload={payload}")
        if not payload:
            log.warning("[Auth] Token validation failed")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
        log.info(f"Extracting sub from token") 
        user_id = int(payload.get("sub"))
        log.warning(f"User id from token id={user_id}")
        user = await user_service.find_account_by_id(user_id)
        if not user:
            log.warning(f"[Auth] User not found for id={user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        log.info(f"[Auth] User validated: id={user.id}, email={user.primary_email}")
        return user

    except HTTPException:
        raise
    except Exception as exc:
        log.error(f"[Auth] Error validating token: {exc}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )


# ----------------------------
# Role-based access dependency
# ----------------------------
def role_required(allowed_roles: list[str]):
    """
    Dependency to ensure the current user has at least one allowed role.
    Usage: Depends(role_required(["ADMIN", "MODERATOR"]))
    """
    async def dependency(user=Depends(get_current_user)):
        user_roles = [role.name for role in user.roles]
        if not any(role in allowed_roles for role in user_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permission denied"
            )
        return user

    return dependency  # <-- just return the async callable

