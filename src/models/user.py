from sqlalchemy import Column, String, Boolean, Integer, DateTime, Index
from sqlalchemy.orm import relationship
from enum import Enum as PyEnum
from .base import BaseEntity
from .associations import user_roles

class UserStatusEnum(str, PyEnum):
    PENDING_VERIFICATION = "pending_verification"
    ACTIVE = "active"
    INACTIVE = "inactive"
    DELETED = "deleted"
    SUSPENDED = "suspended"
    BLOCKED = "blocked"

class User(BaseEntity):
    __tablename__ = "users"
    __table_args__ = (
        Index("idx_user_username", "username"),
        Index("idx_user_primary_email", "primary_email"),
        Index("idx_user_created_at", "created_at"),
        {"schema": "auth"}
    )
    
    username = Column(String(255), nullable=False, unique=True, index=True)
    primary_email = Column(String(320), nullable=False, unique=True, index=True)
    primary_mobile_number = Column(String(20), nullable=True)

    password = Column(String, nullable=False)
    password_login_enabled = Column(Boolean, default=False)

    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    picture = Column(String(500), nullable=True)

    primary_email_verified = Column(Boolean, default=False)
    primary_mobile_number_verified = Column(Boolean, default=False)

    # UPDATED: Use String instead of native Enum
    status = Column(
        String(50), 
        nullable=False, 
        default=UserStatusEnum.PENDING_VERIFICATION.value,
        index=True
    )

    failed_login_attempts = Column(Integer, nullable=False, default=0)
    locked_at = Column(DateTime(timezone=True), nullable=True)

    last_login_ip = Column(String(45), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    # MANY TO MANY
    roles = relationship(
        "Role",
        secondary=user_roles,
        back_populates="users",
        lazy="joined"
    )