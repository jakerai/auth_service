# src/auth/api/router.py
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.schemas.auth_request import SignupRequest, LoginRequest, RefreshTokenRequest
from src.schemas.common.service_request import ServiceRequest
from src.schemas.common.service_response import ServiceResponse
from src.services.auth_service import AuthService
from src.config.database import get_db

router = APIRouter(prefix="/auth", tags=["Authentication"])

def get_auth_service(db: AsyncSession = Depends(get_db)) -> AuthService:
    return AuthService(db)

# -----------------------------
# Signup
# -----------------------------
@router.post(
    "/signup",
    response_model=ServiceResponse[dict],
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user"
)
async def signup(
    request: ServiceRequest[SignupRequest],
    service: AuthService = Depends(get_auth_service),
):
    return await service.signup(request)

# -----------------------------
# Login
# -----------------------------
@router.post(
    "/login",
    response_model=ServiceResponse[dict],
    summary="Login user and get JWT tokens"
)
async def login(
    request: ServiceRequest[LoginRequest],
    service: AuthService = Depends(get_auth_service),
):
    return await service.login(request)

# -----------------------------
# Refresh Token
# -----------------------------
@router.post(
    "/refresh",
    response_model=ServiceResponse[dict],
    summary="Refresh JWT token"
)
async def refresh_token(
    request: ServiceRequest[RefreshTokenRequest],
    service: AuthService = Depends(get_auth_service),
):
    return await service.refresh_token(request)
