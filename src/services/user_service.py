from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, insert
from sqlalchemy.orm import selectinload
from src.models.associations import user_roles
from src.models.user import User, UserStatusEnum
from src.models.user_oauth_providers import OAuthProvider
from src.models.activity import ActionEnum, ResourceEnum
from src.schemas.common.service_response import ServiceResponse, create_response
from src.services.activity_service import ActivityService
from src.config.cache_roles import RoleCache
from src.config.logger import Logger
from src.exception.auth_exceptions import NotFoundException
from src.schemas.user_response import to_user_response
from datetime import datetime, timezone
from src.utils.context import get_client_ip


log = Logger().get_logger()

class UserService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.activity_service = ActivityService(db)

    # ----------------------------
    # ASSIGN ROLES
    # ----------------------------
    async def assign_roles(self, user: User, role_names: list[str]) -> None:
        if not role_names:
            log.info(f"[User:{user.id}] No roles to assign")
            return

        # Getting IDs from Cache (0 DB hits)
        role_ids = [RoleCache.get_role_id(name) for name in role_names]
        log.info(f"[User:{user.id}] Assigning roles: {role_names} -> IDs: {role_ids}")

        # Filtering out roles the user already has
        stmt = select(user_roles.c.role_id).where(user_roles.c.user_id == user.id)
        result = await self.db.execute(stmt)
        existing_role_ids = {r[0] for r in result.fetchall()}
        new_role_ids = [rid for rid in role_ids if rid not in existing_role_ids]

        if not new_role_ids:
            log.info(f"[User:{user.id}] All roles already assigned, skipping insert")
            return

        # Inserting only new roles
        values = [{"user_id": user.id, "role_id": rid} for rid in new_role_ids]
        await self.db.execute(insert(user_roles).values(values))
        log.info(f"[User:{user.id}] Roles assigned successfully: {new_role_ids}")

    # ----------------------------
    # CREATE USER
    # ----------------------------
    async def create_new_account(self, email: str, password: str, first_name: str, last_name: str, roles: List[str]):
        client_ip = get_client_ip()

        new_user = User(
            username=email,
            primary_email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            last_login_at=datetime.now(timezone.utc),
            last_login_ip=client_ip
        )
        try:
            self.db.add(new_user)
            await self.db.flush()
            log.info(f"[User:temp] Creating user {email}")

            await self.assign_roles(new_user, roles)

            await self.db.commit()
            await self.db.refresh(new_user)
            log.info(f"[User:{new_user.id}] User created successfully")

            return new_user

        except Exception as e:
            await self.db.rollback()
            log.error(f"[User:temp] Failed to create user {email}: {e}", exc_info=True)
            raise



    async def update_login(self, user: User):
        try:
            client_ip = get_client_ip()
            user.last_login_at = datetime.now(timezone.utc)
            if client_ip:
                user.last_login_ip = client_ip
            self.db.add(user)
            await self.db.commit()
            await self.db.refresh(user)
            log.info(f"[User:{user.id}] Last login timestamp updated successfully")
            return user
        except Exception as e:
            await self.db.rollback()
            log.error(f"Failed to update login for User {user.id}: {str(e)}")
            raise e

    # ----------------------------
    # CREATE USER Oauth2 (Social)
    # ----------------------------
    async def find_or_create_oauth_user(self, 
                                        email: str, 
                                        password: str, 
                                        provider: str,
                                          provider_user_id: str, 
                                          first_name: str, 
                                          last_name: str, 
                                          roles: List[str]):
        """
        Find an existing user by email or create a new one.
        Links the OAuth provider info if not already linked.
        """

        log.info(f"Creating user with email={email} for provider={provider}")

        # Finding existing user
        user = await self.find_account_by_email(email)  # returns None if not found
        if not user:
            log.debug("User not found. Creating new User.")
            user = await self.create_new_account(email, password, first_name, last_name, roles)
            log.info(f"User created successfully: id={user.id}, email={user.primary_email}")
        else:
            log.debug(f"Existing User found: id={user.id}")
            user = await self.update_login(user)

        # Checking if the provider is already linked
        oauth_accounts = user.oauth_accounts
        provider_exists = any(a.provider == provider for a in oauth_accounts)

        if not provider_exists:
            log.debug(f"User oauth provider '{provider}' not found. Creating new OAuth provider.")
            await self._create_oauth_provider(
                user_id=user.id,
                provider=provider,
                provider_user_id=provider_user_id
            )
        else:
            log.debug(f"User oauth provider '{provider}' already linked.")
        return await to_user_response(user)
    
    
        
    async def _create_oauth_provider(self, user_id: int, provider: str, provider_user_id: str):
        new_provider = OAuthProvider(
            user_id=user_id,
            provider=provider,
            provider_user_id=provider_user_id,
        )

        try:
            self.db.add(new_provider)

            # Flushing to catch DB constraint errors (like duplicate provider_user_id)
            await self.db.flush()

            # Committing the transaction
            await self.db.commit()

            # Refreshing to ensure the object is loaded and safe to use after commit
            await self.db.refresh(new_provider)

            log.info(f"Successfully created OAuth provider for user_id={user_id}")
            return new_provider

        except Exception:
            # Rollback on any failure
            await self.db.rollback()

            log.error(
                f"Failed to create OAuth provider for user_id={user_id}. Transaction rolled back.",
                exc_info=True,
            )
            raise

    # ----------------------------
    # FIND USER BY EMAIL
    # ----------------------------
    async def find_account_by_email(self, email: str) -> User | None:
        stmt = select(User).where(User.primary_email == email).options(selectinload(User.roles))
        result = await self.db.execute(stmt)
        user = result.unique().scalar_one_or_none()
        log.info(f"[User:{getattr(user, 'id', 'N/A')}] Lookup by email: {email} -> Found: {bool(user)}")
        return user
    
    # ----------------------------
    # FIND USER BY ID
    # ----------------------------
    async def find_account_by_id(self, userId: int) -> User | None:
        stmt = select(User).where(User.id == userId).options(selectinload(User.roles))
        result = await self.db.execute(stmt)
        user = result.unique().scalar_one_or_none()
        log.info(f"[User:{getattr(user, 'id', 'N/A')}] Lookup by ID: {id} -> Found: {bool(user)}")
        return user

    # ----------------------------
    # GET PROFILE
    # ----------------------------
    async def get_profile(self, user_id: int) -> ServiceResponse:
        stmt = select(User).where(User.id == user_id)
        result = await self.db.execute(stmt)
        user = result.unique().scalar_one_or_none()

        if not user:
            log.warning(f"[User:{user_id}] Profile not found")
            raise NotFoundException("User not found")

        log.info(f"[User:{user_id}] Profile retrieved")
        return create_response(
            message="Profile retrieved",
            data= await to_user_response(user)
        )

    # ----------------------------
    # UPDATE PROFILE
    # ----------------------------
    async def update_profile(self, user_id: int, username: Optional[str] = None, email: Optional[str] = None) -> ServiceResponse:
        stmt = select(User).where(User.id == user_id)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            log.warning(f"[User:{user_id}] Profile update failed: not found")
            raise NotFoundException("User not found")

        old_data = {"username": user.username, "email": user.primary_email}

        if username:
            user.username = username
        if email:
            user.primary_email = email

        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)

        log.info(f"[User:{user_id}] Profile updated: {old_data} -> { {'username': user.username, 'email': user.primary_email} }")

        await self.activity_service.log(
            user_id=user.id,
            action=ActionEnum.UPDATE,
            resource_type=ResourceEnum.USER,
            resource_id=str(user.id),
            payload={"old": old_data, "new": {"username": user.username, "email": user.primary_email}},
            remarks="Updated profile"
        )

        return create_response(message="Profile updated successfully")

    # ----------------------------
    # UPDATE PROFILE PICTURE
    # ----------------------------
    async def update_picture(self, user_id: int, picture_url: str) -> ServiceResponse:
        stmt = select(User).where(User.id == user_id)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()
        if not user:
            log.warning(f"[User:{user_id}] Update picture failed: not found")
            raise NotFoundException("User not found")

        old_picture = getattr(user, "profile_picture", None)
        user.profile_picture = picture_url

        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)

        log.info(f"[User:{user_id}] Profile picture updated: {old_picture} -> {picture_url}")

        await self.activity_service.log(
            user_id=user.id,
            action=ActionEnum.UPDATE,
            resource_type=ResourceEnum.USER,
            resource_id=str(user.id),
            payload={"old": {"profile_picture": old_picture}, "new": {"profile_picture": picture_url}},
            remarks="Updated profile picture"
        )

        return create_response(message="Profile picture updated successfully")

    # ----------------------------
    # DELETE ACCOUNT
    # ----------------------------
    async def delete_account(self, user_id: int) -> ServiceResponse:
        stmt = select(User).where(User.id == user_id)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()
        if not user:
            log.warning(f"[User:{user_id}] Delete account failed: not found")
            raise NotFoundException("User not found")

        await self.db.delete(user)
        await self.db.commit()

        log.info(f"[User:{user_id}] Account deleted successfully")

        await self.activity_service.log(
            user_id=user.id,
            action=ActionEnum.DELETE,
            resource_type=ResourceEnum.USER,
            resource_id=str(user.id),
            remarks="Deleted account"
        )

        return create_response(message="Account deleted successfully")

    # ----------------------------
    # DEACTIVATE ACCOUNT
    # ----------------------------
    async def deactivate_account(self, user_id: int) -> ServiceResponse:
        stmt = select(User).where(User.id == user_id)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()
        if not user:
            log.warning(f"[User:{user_id}] Deactivate account failed: not found")
            raise NotFoundException("User not found")

        old_status = user.status
        user.status = UserStatusEnum.INACTIVE
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)

        log.info(f"[User:{user_id}] Account deactivated: {old_status} -> {user.status}")

        await self.activity_service.log(
            user_id=user.id,
            action=ActionEnum.UPDATE,
            resource_type=ResourceEnum.USER,
            resource_id=str(user.id),
            payload={"old": {"status": old_status}, "new": {"status": user.status}},
            remarks="Deactivated account"
        )

        return create_response(message="Account deactivated successfully")
