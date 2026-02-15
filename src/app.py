from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.config.database import engine, Base, AsyncSessionLocal, test_connection
from src.api.protected_router import router as protected_router
from src.api.public_router import router as public_router
from src.config.settings import CORS_ORIGINS
from src.exception.auth_exceptions_handler import register_exception_handlers
from src.core.middlewares import RequestIDMiddleware
from src.config.roles_loader import load_roles_permissions
from src.config.logger import Logger
from src.config.cache_roles import RoleCache
from src.security.stores.factory import get_store
from src.security.key_manager import JwtKeyManager
from src.security import jwt_manager as jwt_helper

log = Logger().get_logger()

def create_app() -> FastAPI:
    app = FastAPI(title="Auth Service")
    
    # Registering global exception handlers
    register_exception_handlers(app)
    
    # Adding middlewares
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Including public and protected routers
    app.include_router(public_router)
    app.include_router(protected_router)


    # Startup event: creating schema, tables, then seeding roles
    @app.on_event("startup")
    async def startup():
        log.info("Starting Auth Service...")

        # Test DB connection
        try:
            await test_connection()
        except Exception as e:
            log.critical(f"Database connection failed: {e}")
            raise RuntimeError("Startup failed: cannot connect to database") from e

        # Check registered tables
        registered_tables = list(Base.metadata.tables.keys())
        log.info(f"SQLAlchemy found these tables to create: {registered_tables}")
        if not registered_tables:
            log.critical("No tables found in Base.metadata! Startup cannot continue.")
            raise RuntimeError("Startup failed: no tables found in metadata")

        # Create tables if they don't exist
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            log.info("Database tables creation phase complete.")
        except Exception as e:
            log.critical(f"Failed to create database tables: {e}")
            raise RuntimeError("Startup failed: could not create tables") from e

        # Seed roles & permissions
        log.info("Seeding roles and permissions...")
        try:
            async with AsyncSessionLocal() as session:
                await load_roles_permissions(session)
                log.info("Roles and permissions loaded successfully.")
                log.info("Loading RBAC cache...")
                await RoleCache.initialize(session)
                log.info("RBAC cache ready.")
        except Exception as e:
            log.critical(f"Failed to seed roles/permissions: {e}")
            raise RuntimeError("Startup failed: could not seed roles/permissions") from e
        
        # Key manager
        key_store = get_store()
        key_manager = JwtKeyManager(store=key_store)
        await key_manager.init()
        jwt_helper.jwt_manager = key_manager
        log.info("Auth Service startup complete.")


    return app

   