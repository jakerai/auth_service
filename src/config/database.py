"""
Async database configuration using SQLAlchemy for FastAPI.

Features:
- Async engine creation for PostgreSQL (asyncpg) or other supported DBs.
- Async session factory and dependency injection for FastAPI.
- Optional context manager for easier session management.
- Test function to verify DB connectivity and schema accessibility.
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from contextlib import asynccontextmanager
from src.config.settings import DATABASE_URL
from src.config.logger import Logger

log = Logger().get_logger()

# ---------------------------------------------------------
# Base: single declarative base for all ORM models
# ---------------------------------------------------------
Base = declarative_base()
"""
Declarative Base for all SQLAlchemy models.
All models should inherit from this Base to be registered in metadata.
"""

# ---------------------------------------------------------
# Async Engine
# ---------------------------------------------------------
engine = create_async_engine(
    DATABASE_URL,
    pool_size=20,          # max number of connections in the pool
    max_overflow=10,       # extra connections beyond pool_size
    pool_timeout=30,       # seconds to wait for a connection before throwing
    pool_recycle=1800,     # recycle connections after this time (seconds)
    pool_pre_ping=True,    # check connections before using
    echo=False,            # SQL logging, True for debugging
)
"""
Async engine to interact with the database.
Supports async operations using SQLAlchemy + asyncpg (for PostgreSQL).
"""

# ---------------------------------------------------------
# Async Session Factory
# ---------------------------------------------------------
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,  # prevent auto-expiration of objects on commit
    autoflush=False,         # disable automatic flush to DB
)

# Alias for easier import in other modules
async_session = AsyncSessionLocal

# ---------------------------------------------------------
# Dependency for FastAPI
# ---------------------------------------------------------
async def get_db() -> AsyncSession:
    """
    FastAPI dependency for providing a database session per request.

    Usage in FastAPI endpoint:

    ```python
    @app.get("/users")
    async def list_users(db: AsyncSession = Depends(get_db)):
        result = await db.execute(select(User))
        users = result.scalars().all()
        return users
    ```
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise

# ---------------------------------------------------------
# Async context manager for manual session management
# ---------------------------------------------------------
@asynccontextmanager
async def get_session():
    """
    Async context manager for database sessions with automatic commit/rollback.

    Usage:

    ```python
    async with get_session() as session:
        session.add(new_user)
    ```
    """
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except:
            await session.rollback()
            raise

# ---------------------------------------------------------
# Test database connection
# ---------------------------------------------------------
async def test_connection():
    """
    Test DB connection and check if the 'auth' schema exists.

    Logs success or warning messages accordingly.
    Raises SystemExit if connection fails.
    """
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text("SELECT schema_name FROM information_schema.schemata WHERE schema_name = 'auth'")
            )
            schema_exists = result.scalar()
            if schema_exists:
                log.info(f"Database connection successful. Schema '{schema_exists}' is accessible.")
            else:
                log.warning("Database connected, but schema 'auth' was not found!")
    except SQLAlchemyError as e:
        log.error(f"Database connection failed: {e}")
        raise SystemExit(1)
