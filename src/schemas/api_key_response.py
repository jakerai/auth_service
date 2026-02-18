from pydantic import BaseModel
from datetime import datetime
from src.models.api_key import ApiKey

class ApiKeyResponse(BaseModel):
    id: int
    created_at: datetime
    modified_at: datetime
    key: str
    status: str
    expires_at: datetime

async def to_api_key_response(apiKey: ApiKey) -> ApiKeyResponse:
    if not apiKey:
        return None

    return ApiKeyResponse(
        id=apiKey.id,
        created_at=apiKey.created_at,
        modified_at=apiKey.modified_at,
        key=apiKey.key,
        status=apiKey.status,
        expires_at=apiKey.expires_at
    )

    