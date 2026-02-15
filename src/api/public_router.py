from fastapi import APIRouter
from src.api.v1 import auth_api

# ----------------------------
# Public Router
# ----------------------------
# This router contains endpoints that do NOT require authentication.
# These are open to all users, including unauthenticated requests.
#
# Typical endpoints here:
# - /auth/signup       → Create a new user account
# - /auth/login        → Login and get JWT tokens
# - /health            → Health check for monitoring
#
# These endpoints do not enforce JWT validation, so they are safe
# to expose publicly.
#
# You can include additional public endpoints as needed.

router = APIRouter()

# Including authentication-related APIs
router.include_router(auth_api.router)
