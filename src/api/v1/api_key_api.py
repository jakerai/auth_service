# src/api/v1/api_key_api.py
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from src.schemas.common.service_request import ServiceRequest
from src.schemas.common.service_response import ServiceResponse
from src.schemas.api_key_request import ApiKeyCreateRequest
from src.services.api_key_service import ApiKeyService
from src.security.dependencies import role_required
from src.config.database import get_db

router = APIRouter(prefix="/api-keys", tags=["API Keys"])


# Dependency factory
def get_api_key_service(db: AsyncSession = Depends(get_db)) -> ApiKeyService:
    return ApiKeyService(db)


# ----------------------------
# CREATE API KEY (CUSTOMER ONLY)
# ----------------------------
@router.post("/", response_model=ServiceResponse[dict], status_code=status.HTTP_201_CREATED)
async def create_key(
    request: ServiceRequest[ApiKeyCreateRequest],
    service: ApiKeyService = Depends(get_api_key_service),
    current_user=Depends(role_required(["CUSTOMER"]))
):
    return await service.create_key(current_user.user_id, request.payload)


# ----------------------------
# LIST API KEYS (CUSTOMER & ADMIN)
# ----------------------------
@router.get("/", response_model=ServiceResponse[dict])
async def list_keys(
    service: ApiKeyService = Depends(get_api_key_service),
    current_user=Depends(role_required(["CUSTOMER", "ADMIN"]))
):
    return await service.list_keys(current_user.user_id)


# ----------------------------
# GET API KEY DETAILS (CUSTOMER & ADMIN)
# ----------------------------
@router.get("/{key_id}", response_model=ServiceResponse[dict])
async def get_key(
    key_id: int,
    service: ApiKeyService = Depends(get_api_key_service),
    current_user=Depends(role_required(["CUSTOMER", "ADMIN"]))
):
    return await service.get_key(current_user.user_id, key_id)


# ----------------------------
# REVOKE API KEY (CUSTOMER & ADMIN)
# ----------------------------
@router.post("/{key_id}/revoke", response_model=ServiceResponse[dict])
async def revoke_key(
    key_id: int,
    service: ApiKeyService = Depends(get_api_key_service),
    current_user=Depends(role_required(["CUSTOMER", "ADMIN"]))
):
    return await service.revoke_key(current_user.user_id, key_id)
