from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, insert
from sqlalchemy.orm import selectinload
from src.models.associations import user_roles
from passlib.context import CryptContext
from src.models.user import User, UserStatusEnum
from src.models.role import Role
from src.models.activity import ActionEnum, ResourceEnum
from src.schemas.common.service_response import ServiceResponse, create_response
from src.services.activity_service import ActivityService
from src.config.cache_roles import RoleCache
from src.config.logger import Logger
from src.exception.auth_exceptions import NotFoundException

log = Logger().get_logger()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


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
    async def create_new_account(self, email: str, password: str, first_name: str, last_name: str):
        new_user = User(
            username=email,
            primary_email=email,
            password=pwd_context.hash(password),
            first_name=first_name,
            last_name=last_name,
        )
        try:
            self.db.add(new_user)
            await self.db.flush()
            log.info(f"[User:temp] Creating user {email}")

            await self.assign_roles(new_user, ["USER"])

            await self.db.commit()
            await self.db.refresh(new_user)
            log.info(f"[User:{new_user.id}] User created successfully")

            return new_user

        except Exception as e:
            await self.db.rollback()
            log.error(f"[User:temp] Failed to create user {email}: {e}", exc_info=True)
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
            data={
                "id": user.id,
                "username": user.username,
                "email": user.primary_email,
                "mobile": user.primary_mobile_number,
                "status": user.status
            }
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
