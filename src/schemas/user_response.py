from pydantic import BaseModel, ConfigDict, EmailStr, Field
from typing import List, Optional
from datetime import datetime
from src.models.user import User

class UserResponse(BaseModel):
    id: int
    created_at: datetime
    modified_at: datetime
    last_login_at: datetime
    username: str
    email: EmailStr
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    picture: Optional[str] = None
    status: str
    roles: List[str] = Field(default_factory=set)
    permissions: List[str] = Field(default_factory=set)
    model_config = ConfigDict(from_attributes=True)

async def to_user_response(user: User) -> UserResponse:
    if not user:
        return None

    return UserResponse(
        id=user.id,
        created_at=user.created_at,
        modified_at=user.modified_at,
        last_login_at=user.last_login_at,
        username=user.username,
        email=user.primary_email,
        first_name=user.first_name,
        last_name=user.last_name,
        picture=user.picture,
        status=user.status,
        roles=sorted({r.name for r in user.roles}),
        permissions=sorted({p.type for r in user.roles for p in r.permissions}),
    )

    