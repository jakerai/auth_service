from datetime import datetime, timedelta
from typing import List, Optional
import secrets
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from src.models.api_key import ApiKey, ApiKeyStatusEnum
from src.models.activity import ActionEnum, ResourceEnum
from src.schemas.common.service_response import ServiceResponse, create_response
from src.services.activity_service import ActivityService
from src.config.logger import Logger
from src.exception.auth_exceptions import NotFoundException

log = Logger().get_logger()


class ApiKeyService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.activity_service = ActivityService(db)

    # ----------------------------
    # CREATE API KEY
    # ----------------------------
    async def create_key(self, user_id: int, name: str, expires_in_days: Optional[int] = 30) -> ServiceResponse:
        log.info(f"Creating API key '{name}' for user_id={user_id}")
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(datetime.timezone.utc) + timedelta(days=expires_in_days)

        api_key = ApiKey(
            user_id=user_id,
            name=name,
            token=token,
            status=ApiKeyStatusEnum.ACTIVE,
            expires_at=expires_at
        )

        try:
            self.db.add(api_key)
            await self.db.commit()
            await self.db.refresh(api_key)
            log.info(f"API key created successfully: id={api_key.id} for user_id={user_id}")

            # Log activity
            try:
                await self.activity_service.log(
                    user_id=user_id,
                    action=ActionEnum.CREATE,
                    resource_type=ResourceEnum.API_KEY,
                    resource_id=str(api_key.id),
                    payload={"new": {"name": name, "status": api_key.status}},
                    remarks=f"Created API key '{name}'"
                )
                log.info(f"Activity logged for API key creation: key_id={api_key.id}")
            except Exception as e:
                log.error(f"Failed to log activity for API key creation: {e}")

        except Exception as e:
            await self.db.rollback()
            log.error(f"Failed to create API key '{name}' for user_id={user_id}: {e}")
            raise

        return create_response(message="API key created successfully",
            data={"id": api_key.id, "token": token, "name": name, "expires_at": expires_at}
        )

    # ----------------------------
    # LIST API KEYS
    # ----------------------------
    async def list_keys(self, user_id: int) -> ServiceResponse:
        log.info(f"Listing API keys for user_id={user_id}")
        stmt = select(ApiKey).where(ApiKey.user_id == user_id)
        result = await self.db.execute(stmt)
        keys: List[ApiKey] = result.scalars().all()

        data = [
            {"id": k.id, "name": k.name, "status": k.status, "expires_at": k.expires_at}
            for k in keys
        ]
        log.info(f"Retrieved {len(data)} API keys for user_id={user_id}")
        return create_response(message="API keys retrieved", data=data)

    # ----------------------------
    # GET API KEY DETAILS
    # ----------------------------
    async def get_key(self, user_id: int, key_id: int) -> ServiceResponse:
        log.info(f"Retrieving API key id={key_id} for user_id={user_id}")
        stmt = select(ApiKey).where(ApiKey.id == key_id, ApiKey.user_id == user_id)
        result = await self.db.execute(stmt)
        key = result.scalar_one_or_none()

        if not key:
            log.warning(f"API key not found: key_id={key_id}, user_id={user_id}")
            raise NotFoundException("API key not found")

        log.info(f"API key retrieved successfully: key_id={key.id}")
        return create_response(message="API key retrieved",
            data={"id": key.id, "name": key.name, "status": key.status, "expires_at": key.expires_at}
        )

    # ----------------------------
    # REVOKE API KEY
    # ----------------------------
    async def revoke_key(self, user_id: int, key_id: int) -> ServiceResponse:
        log.info(f"Revoking API key id={key_id} for user_id={user_id}")
        stmt = select(ApiKey).where(ApiKey.id == key_id, ApiKey.user_id == user_id)
        result = await self.db.execute(stmt)
        key = result.scalar_one_or_none()

        if not key:
            log.warning(f"Cannot revoke, API key not found: key_id={key_id}, user_id={user_id}")
            raise NotFoundException("API key not found")

        old_status = key.status
        key.status = ApiKeyStatusEnum.REVOKED
        self.db.add(key)

        try:
            await self.db.commit()
            await self.db.refresh(key)
            log.info(f"API key revoked successfully: key_id={key.id}, old_status={old_status}")

            # Log activity
            try:
                await self.activity_service.log(
                    user_id=user_id,
                    action=ActionEnum.UPDATE,
                    resource_type=ResourceEnum.API_KEY,
                    resource_id=str(key.id),
                    payload={"old": {"status": old_status}, "new": {"status": key.status}},
                    remarks=f"Revoked API key '{key.name}'"
                )
                log.info(f"Activity logged for API key revocation: key_id={key.id}")
            except Exception as e:
                log.error(f"Failed to log activity for API key revocation: {e}")

        except Exception as e:
            await self.db.rollback()
            log.error(f"Failed to revoke API key id={key_id}: {e}")
            raise

        return create_response(message="API key revoked successfully")
