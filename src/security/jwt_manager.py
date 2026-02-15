from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
from jose import jwt, JWTError, ExpiredSignatureError
from fastapi import HTTPException
from src.security.key_manager import JwtKeyManager

# Should be initialized during startup in app.py
jwt_manager: JwtKeyManager = None


def _create_token(payload: Dict[str, Any], expires_delta: timedelta) -> str:
    if jwt_manager is None:
        raise RuntimeError("JWT Manager not initialized!")

    now = datetime.now(timezone.utc)
    payload.update({"iat": now, "exp": now + expires_delta})

    private_key = jwt_manager.get_private_key()
    kid = jwt_manager.get_current_kid()
    headers = {"kid": kid}

    return jwt.encode(payload, private_key, algorithm="RS256", headers=headers)


def create_access_token(user_id: int, roles: List[str]) -> str:
    payload = {"sub": str(user_id), "roles": roles, "type": "access"}
    return _create_token(payload, timedelta(minutes=60))


def create_refresh_token(user_id: int, roles: List[str]) -> str:
    payload = {"sub": str(user_id), "roles": roles, "type": "refresh"}
    return _create_token(payload, timedelta(days=7))


async def decode_token(token: str) -> Dict[str, Any]:
    if jwt_manager is None:
        raise RuntimeError("JWT Manager not initialized!")

    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")

        if not kid:
            raise HTTPException(status_code=401, detail="Missing kid in JWT header")

        public_key = await jwt_manager.get_public_key(kid)

        return jwt.decode(token, public_key, algorithms=["RS256"])

    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
