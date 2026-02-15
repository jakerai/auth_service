from typing import Optional, Dict
from sqlalchemy.ext.asyncio import AsyncSession
from src.models.activity import Activity, ActionEnum, ResourceEnum
from src.config.logger import Logger

log = Logger().get_logger()


class ActivityService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def log(
        self,
        user_id: Optional[int],
        action: ActionEnum,
        resource_type: ResourceEnum = ResourceEnum.USER,
        resource_id: Optional[str] = None,
        payload: Optional[Dict] = None,
        remarks: Optional[str] = None,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ):
        """
        Log user or system activity asynchronously with detailed trace logs
        """
        log.info(
            f"Starting activity log: user_id={user_id}, action={action}, "
            f"resource_type={resource_type}, resource_id={resource_id}"
        )

        try:
            log_entry = Activity(
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id or str(user_id) if user_id else None,
                payload=payload,
                remarks=remarks,
                ip=ip,
                user_agent=user_agent,
            )

            self.db.add(log_entry)
            await self.db.commit()
            await self.db.refresh(log_entry)

            log.info(
                f"Activity logged successfully: id={log_entry.id}, user_id={user_id}, "
                f"action={action}, resource_id={log_entry.resource_id}"
            )
            return log_entry

        except Exception as e:
            await self.db.rollback()
            log.error(
                f"Failed to log activity: user_id={user_id}, action={action}, "
                f"resource_type={resource_type}, resource_id={resource_id}, error={e}"
            )
            raise
