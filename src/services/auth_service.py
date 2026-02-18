from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from src.models.user import User
from src.models.activity import ActionEnum, ResourceEnum
from src.schemas.common.service_response import ServiceResponse, create_response
from src.services.activity_service import ActivityService
from src.services.user_service import UserService
from src.exception.auth_exceptions import UnauthorizedException, NotFoundException, UserAlreadyExistsException
from src.security.jwt_manager import create_access_token, create_refresh_token, decode_token
from src.config.logger import Logger
from src.utils.password_generator import PasswordGenerator
from typing import Optional, Dict, Any


log = Logger().get_logger()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.user_service = UserService(db)
        self.activity_service = ActivityService(db)

    async def signup(self, request) -> ServiceResponse:
        payload = request.payload
        log.info(f"Signup requested for email: {payload.email}")
        # Checking if user exists by email
        existing_user = await self.user_service.find_account_by_email(payload.email)
        if existing_user:
            log.warning(f"Signup failed: email already registered - {payload.email}")
            raise UserAlreadyExistsException("Email is already registered")
        
        # Create new user
        new_user = await self.user_service.create_new_account(
            email=payload.email,
            password=pwd_context.hash(payload.password),
            first_name=payload.first_name,
            last_name=payload.last_name, 
            roles=["USER"]
        )
        log.info(f"New user created: id={new_user.id}, email={new_user.primary_email}")

        # Log activity (non-blocking)
        try:
            await self.activity_service.log(
                user_id=new_user.id,
                action=ActionEnum.CREATE,
                resource_type=ResourceEnum.USER,
                resource_id=str(new_user.id),
                payload={"new": {"email": new_user.primary_email}},
                remarks="New user signup",
            )
            log.info(f"Signup activity logged for user_id={new_user.id}")
        except Exception as e:
            log.error(f"Failed to log signup activity for user_id={new_user.id}: {e}")

        # Return response
        data = {
            "id": new_user.id,
            "email": new_user.primary_email,
            "first_name": new_user.first_name,
            "last_name": new_user.last_name,
        }

        return create_response(
            data=data,
            message="Account created successfully",
        )

    async def login(self, request) -> ServiceResponse:
        payload = request.payload
        log.info(f"Login requested for email: {payload.email}")
        
        user = await self.user_service.find_account_by_email(payload.email)

        if not user or not pwd_context.verify(payload.password, user.password):
            log.warning(f"Unauthorized login attempt for email: {payload.email}")
            raise UnauthorizedException("Email or password is incorrect")
        
        # Log activity
        try:
            await self.activity_service.log(
                user_id=user.id,
                action=ActionEnum.LOGIN,
                resource_type=ResourceEnum.USER,
                resource_id=str(user.id),
                remarks="User login"
            )
            log.info(f"Login activity logged for user_id={user.id}")
        except Exception as e:
            log.error(f"Failed to log login activity for user_id={user.id}: {e}")

        # Extract role names
        roles = [role.name for role in user.roles]
        access = create_access_token(user.id, roles)
        refresh = create_refresh_token(user.id, roles)
        log.info(f"Tokens generated for user_id={user.id}")

        data = {"access_token": access, "refresh_token": refresh}
        return create_response(
            data=data,
            message="Login successful",
        )

    async def refresh_token(self, request) -> ServiceResponse:
        log.info("Token refresh requested")
        try:
            payload = decode_token(request.refresh_token)
        except Exception:
            log.warning("Invalid refresh token attempt")
            raise UnauthorizedException("Invalid refresh token")

        if payload.get("type") != "refresh":
            log.warning("Invalid token type for refresh")
            raise UnauthorizedException("Invalid token type")

        user_id = payload.get("sub")
        stmt = select(User).where(User.id == user_id)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()
        if not user:
            log.warning(f"Token refresh failed, user not found: id={user_id}")
            raise NotFoundException("User not found")

        roles = [role.name for role in user.roles]
        access = create_access_token(user.id, roles)
        refresh = create_refresh_token(user.id, roles)
        log.info(f"Tokens refreshed for user_id={user.id}")

        # Log activity
        try:
            await self.activity_service.log(
                user_id=user.id,
                action=ActionEnum.LOGIN,
                resource_type=ResourceEnum.USER,
                resource_id=str(user.id),
                remarks="Refreshed access token"
            )
            log.info(f"Token refresh activity logged for user_id={user.id}")
        except Exception as e:
            log.error(f"Failed to log token refresh activity for user_id={user.id}: {e}")

        data = {"access_token": access, "refresh_token": refresh}
        return create_response(
            data=data,
            message="Token refreshed",
        )
    
    
    # ------------------------------------------------------------------
    # Social Login / Register
    # ------------------------------------------------------------------
    async def oauth2_authenticate(self, sso_user, provider: str):
        """
        Authenticate or auto-register a user coming from OAuth2 provider.
        """
        profile = await self._extract_oauth_profile(provider, sso_user)

        if not profile.get("email"):
            raise UnauthorizedException("Email not provided by provider")

        enriched_user = await self.user_service.find_or_create_oauth_user(
            email=profile["email"],
            password=pwd_context.hash(PasswordGenerator.generate()),
            provider=provider,
            provider_user_id=profile.get("provider_user_id"),
            first_name=profile.get("first_name") or "",
            last_name=profile.get("last_name") or "",
            roles=["USER"]
        )
        log.info(f"Oauth user CREATE/UPDATE: id={enriched_user.id}, email={enriched_user.email}")
        
        try:
            await self.activity_service.log(
                user_id=enriched_user.id,
                action=ActionEnum.CREATE,
                resource_type=ResourceEnum.USER,
                resource_id=str(enriched_user.id),
                payload={"new": {"email": enriched_user.email}},
                remarks="OAuth2 New user signup",
            )
            log.info(f"OAuth2 Signup activity logged for user_id={enriched_user.id}")
        except Exception as e:
            log.error(f"Failed to log OAuth2 signup activity for user_id={enriched_user.id}: {e}")
        
        access = create_access_token(enriched_user.id, enriched_user.roles)
        refresh = create_refresh_token(enriched_user.id, enriched_user.roles)
        log.info(f"Tokens generated for OAuth2 user_id={enriched_user.id}")

        return {"access_token": access, "refresh_token": refresh}
        

    async def _extract_oauth_profile(self, provider: str, sso_user: Any) -> Dict[str, Optional[str]]:
        def get_attr(obj, key):
            if isinstance(obj, dict):
                return obj.get(key)
            return getattr(obj, key, None)

        provider = provider.lower()
        
        provider_user_id = get_attr(sso_user, "id") or get_attr(sso_user, "sub")
        email = get_attr(sso_user, "email")
        display_name = get_attr(sso_user, "display_name")
        
        first_name = get_attr(sso_user, "first_name")
        last_name = get_attr(sso_user, "last_name")

        if provider == "google":
            first_name = first_name or get_attr(sso_user, "given_name")
            last_name = last_name or get_attr(sso_user, "family_name")
            
        elif provider == "github":
            provider_user_id = str(provider_user_id) if provider_user_id is not None else None
            
        elif provider == "twitter":
            if not email:
                username = get_attr(sso_user, "username") or "user"
                email = f"{username}@twitter.com"

        # Fallback from display_name
        if not first_name and display_name:
            parts = display_name.strip().split(" ", 1)
            first_name = parts[0]
            last_name = last_name or (parts[1] if len(parts) > 1 else "")

        if not provider_user_id:
            raise ValueError(f"Could not extract a unique user ID from {provider} profile.")

        return {
            "provider": provider,
            "provider_user_id": str(provider_user_id),
            "email": email,
            "first_name": first_name or "OAuthUser",
            "last_name": last_name or ""
        }
