from sqlalchemy import Table, Column, Integer, ForeignKey
from .base import BaseEntity


# User ↔ Role
user_roles = Table(
    "user_roles",
    BaseEntity.metadata,
    Column("user_id", Integer, ForeignKey("auth.users.id"), primary_key=True),
    Column("role_id", Integer, ForeignKey("auth.roles.id"), primary_key=True),
    schema="auth",
)


# Role ↔ Permission
role_permissions = Table(
    "role_permissions",
    BaseEntity.metadata,
    Column("role_id", Integer, ForeignKey("auth.roles.id"), primary_key=True),
    Column("permission_id", Integer, ForeignKey("auth.permissions.id"), primary_key=True),
    schema="auth",
)
