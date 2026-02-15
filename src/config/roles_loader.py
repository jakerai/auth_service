import json
from pathlib import Path
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from src.models.role import Role
from src.models.permission import Permission
from src.config.logger import Logger

log = Logger().get_logger()

# Path to JSON file containing roles and permissions
ROLES_FILE = Path(__file__).parent / "roles.json"


async def load_roles_permissions(db: AsyncSession) -> None:
    """
    Seed roles and permissions from roles.json into the database.

    Features:
        - Async-safe with AsyncSession
        - Idempotent: only inserts missing roles/permissions
        - Uses selectinload + unique() to avoid async lazy-loading issues
        - Logs all creations and attachments

    Parameters:
        db (AsyncSession): The SQLAlchemy async session

    Raises:
        RuntimeError: If any failure occurs during seeding
    """

    # -----------------------------
    # Check if roles.json exists
    # -----------------------------
    if not ROLES_FILE.exists():
        log.warning("roles.json file not found. Skipping role seeding.")
        return

    # Load JSON file
    with open(ROLES_FILE, "r", encoding="utf-8") as f:
        config = json.load(f)

    roles_data = config.get("roles", [])
    if not roles_data:
        log.warning("roles.json contains no roles. Skipping seeding.")
        return

    log.info("Starting role & permission seeding...")

    # -----------------------------
    # Preload existing roles and permissions
    # -----------------------------
    try:
        role_result = await db.execute(
            select(Role).options(selectinload(Role.permissions))
        )
        # Fix eager-load duplication by using unique()
        existing_roles = {r.name: r for r in role_result.unique().scalars().all()}

        perm_result = await db.execute(select(Permission))
        existing_permissions = {p.type: p for p in perm_result.unique().scalars().all()}

    except Exception as e:
        log.critical(f"Failed to preload roles/permissions from DB: {e}")
        raise RuntimeError("Cannot preload existing roles/permissions") from e

    # -----------------------------
    # Create missing permissions
    # -----------------------------
    new_permissions_count = 0
    for role in roles_data:
        for perm_name in role.get("permissions", []):
            if perm_name not in existing_permissions:
                perm = Permission(type=perm_name)
                db.add(perm)
                existing_permissions[perm_name] = perm
                new_permissions_count += 1

    if new_permissions_count > 0:
        log.info(f"Creating {new_permissions_count} new permissions from roles.json")
        try:
            await db.flush()  # ensure IDs available for role mappings
        except Exception as e:
            log.critical(f"Failed to flush new permissions: {e}")
            raise RuntimeError("Cannot flush new permissions") from e

    # -----------------------------
    # Create missing roles and attach permissions
    # -----------------------------
    new_roles = []
    try:
        for role_entry in roles_data:
            role_name = role_entry["name"]

            # Get existing role or create new
            if role_name in existing_roles:
                role_obj = existing_roles[role_name]
            else:
                role_obj = Role(name=role_name)
                role_obj.permissions = []  # avoid lazy-load issues
                db.add(role_obj)
                existing_roles[role_name] = role_obj
                new_roles.append(role_name)
                log.info(f"Created role: {role_name}")

            # Current permissions attached to role
            current_perm_types = {p.type for p in role_obj.permissions}

            # Attach missing permissions
            for perm_name in role_entry.get("permissions", []):
                if perm_name not in current_perm_types:
                    role_obj.permissions.append(existing_permissions[perm_name])
                    log.info(f"Attached permission '{perm_name}' -> role '{role_name}'")

    except Exception as e:
        log.critical(f"Failed to create roles or attach permissions: {e}")
        raise RuntimeError("Cannot create roles or attach permissions") from e

    if new_roles:
        log.info(f"Created roles: {new_roles}")

    # -----------------------------
    # Commit transaction
    # -----------------------------
    try:
        await db.commit()
        log.info("Role & permission seeding completed successfully.")
    except Exception as e:
        await db.rollback()
        log.critical(f"Failed to commit role/permission seeding: {e}")
        raise RuntimeError("Cannot commit role/permission seeding") from e
