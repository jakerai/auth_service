from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Index
from sqlalchemy.orm import relationship
from .base import BaseEntity
from enum import Enum as PyEnum
from datetime import datetime, timezone


class APIKeyStatusEnum(str, PyEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class APIKey(BaseEntity):
    __tablename__ = "api_keys"
    __table_args__ = (
        Index("idx_api_keys_key", "key", unique=True),
        Index("idx_api_keys_user_id", "user_id"),
        Index("idx_api_keys_status", "status"),
        Index("idx_api_keys_expires_at", "expires_at"),
        {"schema": "auth"}
    )
    
    user_id = Column(Integer, ForeignKey("auth.users.id"), nullable=False, index=True)
    key = Column(String(255), nullable=False, unique=True, index=True)
    
    # RECOMMENDED CHANGE: Use String instead of Enum type
    # This prevents Postgres 'Type' conflicts while keeping Python safety
    status = Column(
        String(50), 
        nullable=False,
        # Default value is the string "active"
        server_default=APIKeyStatusEnum.ACTIVE.value,
        index=True
    )
    
    expires_at = Column(
        DateTime(timezone=True),
        nullable=True,
        # UTC default using lambda to ensure it's evaluated at runtime
        default=lambda: datetime.now(timezone.utc)
    )