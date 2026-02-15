from typing import Dict, Set
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.role import Role


class RoleCache:
    """
    In-memory RBAC cache.

    Stores:
        role_name -> role_id
        role_id   -> set(permission_names)
    """

    _roles_to_ids: Dict[str, int] = {}
    _role_permissions: Dict[int, Set[str]] = {}
    _is_initialized: bool = False

    # ---------------------------------------------------------
    # Initialization
    # ---------------------------------------------------------
    @classmethod
    async def initialize(cls, db: AsyncSession) -> None:
        """
        Load roles & permissions from DB into memory.
        Should be called once at application startup.
        """
        stmt = select(Role).options(selectinload(Role.permissions))
        result = await db.execute(stmt)

        # unique() protects from accidental eager-load duplication
        roles = result.unique().scalars().all()

        cls._roles_to_ids = {r.name.upper(): r.id for r in roles}

        cls._role_permissions = {
            r.id: {p.type.upper() for p in r.permissions}
            for r in roles
        }

        cls._is_initialized = True

    # ---------------------------------------------------------
    # Internal safety
    # ---------------------------------------------------------
    @classmethod
    def _ensure_initialized(cls):
        if not cls._is_initialized:
            raise RuntimeError("RoleCache is not initialized")

    # ---------------------------------------------------------
    # Public API
    # ---------------------------------------------------------
    @classmethod
    def get_role_id(cls, role_name: str) -> int:
        cls._ensure_initialized()

        role_id = cls._roles_to_ids.get(role_name.upper())
        if role_id is None:
            raise ValueError(f"Role '{role_name}' not found in cache")

        return role_id

    @classmethod
    def get_permissions_for_role(cls, role_id: int) -> Set[str]:
        cls._ensure_initialized()
        return cls._role_permissions.get(role_id, set())

    @classmethod
    def role_has_permission(cls, role_id: int, permission: str) -> bool:
        """
        Fast permission check.
        """
        cls._ensure_initialized()
        return permission.upper() in cls._role_permissions.get(role_id, set())

    # ---------------------------------------------------------
    # Optional utilities
    # ---------------------------------------------------------
    @classmethod
    def clear(cls):
        """Used for reloads/testing."""
        cls._roles_to_ids.clear()
        cls._role_permissions.clear()
        cls._is_initialized = False
