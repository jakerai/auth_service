# src/security/stores/db_store.py
from sqlalchemy import select, update, insert
from sqlalchemy.dialects.postgresql import JSONB
from src.models.jwt_key import JwtKeyTable
from src.config.database import async_session
from .base import JwtKeyStore
from src.utils.key_serialization import serialize_keys, deserialize_keys
from src.config.logger import Logger
import json

log = Logger().get_logger()


class DatabaseJwtKeyStore(JwtKeyStore):
    """
    PostgreSQL-based JWT key store.
    - Single row only
    - 'keys' column is a JSONB array with max 2 objects: CURRENT, PREVIOUS
    """

    async def find_keys(self):
        """Retrieve keys from DB and deserialize."""
        async with async_session() as db:
            log.info("[DatabaseJwtKeyStore] Retrieving keys from DB...")
            result = await db.execute(select(JwtKeyTable).limit(1))
            row = result.scalar_one_or_none()
            if row and row.keys:
                keys = deserialize_keys(row.keys)
                log.info(f"[DatabaseJwtKeyStore] Keys found: {len(keys.get('keys', []))} entries")
                return keys
            log.info("[DatabaseJwtKeyStore] No keys found in DB")
            return None

    async def save_keys(self, keys: dict):
        """
        Insert or update the single row with keys array.
        """
        keys_json = serialize_keys(keys)
        async with async_session() as db:
            row = await db.execute(select(JwtKeyTable).limit(1))
            row = row.scalar_one_or_none()

            if row:
                log.info(f"[DatabaseJwtKeyStore] Updating existing row with {len(keys.get('keys', []))} keys...")
                stmt = update(JwtKeyTable).values(keys=keys_json)
                await db.execute(stmt)
            else:
                log.info(f"[DatabaseJwtKeyStore] Inserting new row with {len(keys.get('keys', []))} keys...")
                stmt = insert(JwtKeyTable).values(keys=keys_json)
                await db.execute(stmt)

            await db.commit()
            log.info("[DatabaseJwtKeyStore] Keys saved successfully.")

    async def rotate_keys_atomically(self, expected_current_kid: str, new_keys: dict) -> bool:
        keys_json = serialize_keys(new_keys)
        
        # Define the criteria as an object, not a list
        # PostgreSQL @> checks if the right side is a subset of the left side
        filter_criteria = {
            "keys": [
                {"kid": expected_current_kid, "status": "CURRENT"}
            ]
        }

        async with async_session() as db:
            stmt = (
                update(JwtKeyTable)
                # Ensure we target the right record (usually ID 1 for single-row stores)
                .where(JwtKeyTable.id == 1) 
                # This matches if the 'keys' array contains an object with this kid and status
                .where(JwtKeyTable.keys.contains(filter_criteria))
                .values(keys=keys_json)
            )

            result = await db.execute(stmt)
            await db.commit()

            if result.rowcount > 0:
                log.info(f"[DatabaseJwtKeyStore] Rotation successful for kid={expected_current_kid}")
                return True
            else:
                # If this fails, it's usually because another instance updated the 'kid' already
                log.warning(f"[DatabaseJwtKeyStore] Rotation skipped: CURRENT kid {expected_current_kid} not found or already rotated")
                return False
