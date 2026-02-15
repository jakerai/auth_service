from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from src.models.user import User
from src.models.activity import ActionEnum, ResourceEnum
from src.schemas.common.service_response import ServiceResponse, create_response
from src.services.activity_service import ActivityService
from src.services.user_service import UserService
from src.exception.auth_exceptions import UnauthorizedException, UserAlreadyExistsException, NotFoundException
from src.security.jwt_manager import create_access_token, create_refresh_token, decode_token
from src.config.logger import Logger

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

        # Check if user exists by email
        existing_user = await self.user_service.find_account_by_email(payload.email)
        if existing_user:
            log.warning(f"Signup failed: email already registered - {payload.email}")
            raise UserAlreadyExistsException("Email is already registered")

        # Create new user
        new_user = await self.user_service.create_new_account(
            email=payload.email,
            password=payload.password,
            first_name=payload.first_name,
            last_name=payload.last_name,
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
