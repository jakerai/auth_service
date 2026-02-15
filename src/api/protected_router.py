from fastapi import APIRouter, Depends
from src.security.dependencies import get_current_user
from src.api.v1 import api_key_api, user_api

# ----------------------------
# Protected Router
# ----------------------------
# This router applies to all endpoints that require authentication.
# By passing `dependencies=[Depends(get_current_user)]`, all routes included
# here automatically enforce JWT-based authentication.
#
# Any user accessing these endpoints must provide a valid access token
# (usually via the Authorization header: "Bearer <token>").
#
# Individual endpoints can also add role-based restrictions using
# Depends(role_required([...])) if needed.
#
# Examples of protected endpoints:
# - /users/profile
# - /api_keys
# - /users/update
# 

router = APIRouter(dependencies=[Depends(get_current_user)])

# Including user-related APIs
router.include_router(user_api.router)

# Including API key management APIs
router.include_router(api_key_api.router)
