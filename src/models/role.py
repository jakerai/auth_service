from sqlalchemy import Column, String, Index
from sqlalchemy.orm import relationship

from .base import BaseEntity
from .associations import user_roles, role_permissions


class Role(BaseEntity):
    __tablename__ = "roles"
    __table_args__ = (
        Index("idx_role_name", "name"),
        {"schema": "auth"}
    )
    
    name = Column(String(50), nullable=False, unique=True, index=True)

    # User relation
    users = relationship(
        "User",
        secondary=user_roles,
        back_populates="roles",
        lazy="joined"
    )

    # Permission relation
    permissions = relationship(
        "Permission",
        secondary=role_permissions,
        back_populates="roles",
        lazy="joined",
        cascade="save-update, merge"
    )

    # helper methods
    def add_permission(self, permission):
        if permission not in self.permissions:
            self.permissions.append(permission)

    def remove_permission(self, permission):
        if permission in self.permissions:
            self.permissions.remove(permission)

    def has_permission(self, permission) -> bool:
        return permission in self.permissions
