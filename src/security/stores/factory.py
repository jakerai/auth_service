import threading
from src.config.settings import JWT_KEY_SOURCE
from .db_store import DatabaseJwtKeyStore
from .aws_store import AwsJwtKeyStore
from src.config.logger import Logger

log = Logger().get_logger()

# Thread-safe lock and private instance holder
_store_instance = None
_lock = threading.Lock()

def get_store():
    """
    Returns a singleton instance of the configured JWT Key Store.
    Thread-safe and defaults to Database.
    """
    global _store_instance

    # Double-checked locking pattern for performance
    if _store_instance is not None:
        return _store_instance

    with _lock:
        if _store_instance is None:
            source = (JWT_KEY_SOURCE or "db").lower()
            log.info(f"Jwt key source = {source}")
            if source == "aws":
                log.info("[JwtKeyStoreFactory] Initializing AWS Secrets Manager Store")
                _store_instance = AwsJwtKeyStore()
            elif source == "db":
                log.info("[JwtKeyStoreFactory] Initializing Database Store")
                _store_instance = DatabaseJwtKeyStore()
            else:
                log.warning(
                    f"[JwtKeyStoreFactory] Unknown source '{source}', falling back to DB"
                )
                _store_instance = DatabaseJwtKeyStore()

    return _store_instance