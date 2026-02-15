from sqlalchemy import Column, String, Index
from sqlalchemy.orm import relationship

from .base import BaseEntity
from .associations import role_permissions


class Permission(BaseEntity):
    __tablename__ = "permissions"
    __table_args__ = (
        Index("idx_permission", "type"),
        {"schema": "auth"}
    )
    
    type = Column(String(50), nullable=False, unique=True, index=True)

    roles = relationship(
        "Role",
        secondary=role_permissions,
        back_populates="permissions",
        lazy="joined"
    )
