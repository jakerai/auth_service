"""
Author: Vishal Rai
Description: Implements OAuth2 login using fastapi-sso for Google and Facebook,
with JWT generation and RBAC integration.
"""

from fastapi import APIRouter, Request, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.responses import RedirectResponse
from starlette import status
from src.services.auth_service import AuthService
from src.config.database import get_db
from fastapi_sso.sso.google import GoogleSSO
from fastapi_sso.sso.facebook import FacebookSSO
from src.config.settings import (
    GOOGLE_CLIENT_ID, 
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI,
    FACEBOOK_CLIENT_ID,
    FACEBOOK_CLIENT_SECRET,
    FACEBOOK_REDIRECT_URI,
    OAUTH2_ALLOWED_REDIRECTS)
from urllib.parse import urlparse
from src.config.logger import Logger

log = Logger().get_logger()
router = APIRouter(prefix="/oauth2", tags=["OAuth2"])

# -----------------------------
# Dependency
# -----------------------------
def get_auth_service(db: AsyncSession = Depends(get_db)) -> AuthService:
    return AuthService(db)


# ------------------------------------------------------------------
# Configure Providers
# ------------------------------------------------------------------
google_sso = GoogleSSO(
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    redirect_uri=GOOGLE_REDIRECT_URI,
)

facebook_sso = FacebookSSO(
    client_id=FACEBOOK_CLIENT_ID,
    client_secret=FACEBOOK_CLIENT_SECRET,
    redirect_uri=FACEBOOK_REDIRECT_URI,
)


providers = {
    "google": google_sso,
    "facebook": facebook_sso,
}

def is_valid_redirect(uri: str) -> bool:
    try:
        parsed = urlparse(uri)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        return base_url in OAUTH2_ALLOWED_REDIRECTS
    except Exception:
        return False
    
# ------------------------------------------------------------------
# Login → Redirect user to provider
# ------------------------------------------------------------------
@router.get("/login/{provider}")
async def oauth_login(provider: str, request: Request):
    sso = providers.get(provider)

    if not sso:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    # getting redirect URI from request
    redirect_uri = request.query_params.get("redirect_uri")
    
    if not redirect_uri:
        raise HTTPException(status_code=400, detail="Missing redirect_uri")
    # Validating redirect URI
    if not is_valid_redirect(redirect_uri):
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    
    async with sso:
        return await sso.get_login_redirect(state=redirect_uri)


# ------------------------------------------------------------------
# Callback → Provider returns user info
# ------------------------------------------------------------------
@router.get("/callback/{provider}")
async def oauth_callback(provider: str, request: Request, service: AuthService = Depends(get_auth_service)):
    sso = providers.get(provider)
    if not sso:
        raise HTTPException(status_code=400, detail="Unsupported provider")

    async with sso:
        user = await sso.verify_and_process(request)
        
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    oauth2_result = await service.oauth2_authenticate(user, provider)
    access_token = oauth2_result["access_token"]
    refresh_token = oauth2_result["refresh_token"]
    
    redirect_uri = request.query_params.get("state")
    log.info("Redirect to "+redirect_uri)
    if not is_valid_redirect(redirect_uri):
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    
    response = RedirectResponse(
        url=redirect_uri,
        status_code=status.HTTP_302_FOUND,
    )
    
    # Set secure cookies
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,  # True in production (HTTPS)
        samesite="lax", #frontend is different
        max_age=60 * 15,  # 15 minutes
    )

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,  # True in production
        samesite="lax",
        max_age=60 * 60 * 24 * 7,  # 7 days
    )
    return response
    