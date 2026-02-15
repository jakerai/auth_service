import os
from dotenv import load_dotenv

load_dotenv()

# Database
POSTGRES_USER = os.getenv("POSTGRES_USER", "postgres")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "postgres")
POSTGRES_DB = os.getenv("POSTGRES_DB", "document_db")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "127.0.0.1")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", 5432))

DATABASE_URL = f"postgresql+asyncpg://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"

# JWT
# Note: In production, do NOT provide a default for SECRET_KEY. 
# Force the app to crash if it's missing to prevent insecure deployments.
JWT_KEY_SOURCE = os.getenv("JWT_KEY_SOURCE", "db") # db for database and aws for aws secret manager
JWT_MASTER_SECRET = os.getenv("JWT_MASTER_SECRET") 
if not JWT_MASTER_SECRET:
    raise ValueError("No JWT_MASTER_SECRET set for application")

JWT_ALGORITHM = "RSA256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7  # for the long-lived refresh token
JWT_RSA_KEY_SIZE = 2048 #Key size in bits (2048 recommended)
JWT_KEY_TTL_SECONDS = 240  # Recommended: 1 hour (longer TTL makes rotation safer)
JWT_ROTATION_THRESHOLD_SECONDS = 60  # Start rotating 1 minute before expiry
JWT_ROTATION_CHECK_INTERVAL_SECONDS = 60 # Check every 2 minutes
# CORS
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:8005").split(",")
