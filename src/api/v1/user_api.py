from fastapi import APIRouter, Depends, status, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from src.config.database import get_db
from src.security.dependencies import role_required
from src.services.user_service import UserService
from src.schemas.common.service_request import ServiceRequest
from src.schemas.user_request import UserUpdateRequest
from src.config.logger import Logger

log = Logger().get_logger()

router = APIRouter(prefix="/users", tags=["Users"])

# Dependency factory
def get_user_service(db: AsyncSession = Depends(get_db)) -> UserService:
    return UserService(db)


# ----------------------------
# GET PROFILE
# ----------------------------
@router.get("/profile")
async def get_profile(
    current_user = Depends(role_required(["ADMIN", "USER"])),
    service: UserService = Depends(get_user_service)
):
    log.info(f"[Users] GET /profile called by user_id={current_user.id}")
    return await service.get_profile(current_user.id)


# ----------------------------
# UPDATE PROFILE
# ----------------------------
@router.put("/update")
async def update_profile(
    request: ServiceRequest[UserUpdateRequest],
    current_user = Depends(role_required(["ADMIN", "CUSTOMER"])),
    service: UserService = Depends(get_user_service)
):
    log.info(f"[Users] PUT /update called by user_id={current_user.id}")
    return await service.update_profile(
        current_user.id,
        username=request.payload.username if request.payload.username else None,
        email=request.payload.email if request.payload.email else None
    )


# ----------------------------
# UPDATE PROFILE PICTURE
# ----------------------------
@router.put("/profile/picture")
async def update_picture(
    picture: UploadFile = File(...),
    current_user = Depends(role_required(["ADMIN", "CUSTOMER"])),
    service: UserService = Depends(get_user_service)
):
    log.info(f"[Users] PUT /profile/picture called by user_id={current_user.id}, file={picture.filename}")
   
    picture_url = f"https://cdn.example.com/{picture.filename}"
    return await service.update_picture(current_user.id, picture_url)


# ----------------------------
# DELETE ACCOUNT
# ----------------------------
@router.delete("/account")
async def delete_account(
    current_user = Depends(role_required(["ADMIN", "CUSTOMER"])),
    service: UserService = Depends(get_user_service)
):
    log.info(f"[Users] DELETE /account called by user_id={current_user.id}")
    return await service.delete_account(current_user.id)


# ----------------------------
# DEACTIVATE ACCOUNT
# ----------------------------
@router.post("/account/deactivate")
async def deactivate_account(
    current_user = Depends(role_required(["ADMIN", "CUSTOMER"])),
    service: UserService = Depends(get_user_service)
):
    log.info(f"[Users] POST /account/deactivate called by user_id={current_user.id}")
    return await service.deactivate_account(current_user.id)
