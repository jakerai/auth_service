from datetime import datetime, timezone
from typing import Any

def serialize_keys(keys: Any) -> Any:
    """
    Recursively convert datetime objects to ISO strings for JSON storage.
    """
    if isinstance(keys, dict):
        return {k: serialize_keys(v) for k, v in keys.items()}
    elif isinstance(keys, list):
        return [serialize_keys(v) for v in keys]
    elif isinstance(keys, datetime):
        # Ensure UTC timezone
        if keys.tzinfo is None:
            keys = keys.replace(tzinfo=timezone.utc)
        return keys.isoformat()
    else:
        return keys

def deserialize_keys(keys: Any) -> Any:
    """
    Recursively convert ISO datetime strings back to datetime objects.
    """
    if isinstance(keys, dict):
        return {k: deserialize_keys(v) for k, v in keys.items()}
    elif isinstance(keys, list):
        return [deserialize_keys(v) for v in keys]
    elif isinstance(keys, str):
        try:
            return datetime.fromisoformat(keys)
        except ValueError:
            return keys  # Not a datetime string
    else:
        return keys
