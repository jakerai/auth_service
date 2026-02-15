from pydantic import BaseModel, EmailStr, Field
from typing import Optional


# =========================================================
# Shared properties
# =========================================================
class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    primary_mobile: Optional[str] = None
    role_id: int


# =========================================================
# Create
# =========================================================
class UserCreateRequest(UserBase):
    password: str = Field(..., min_length=8, max_length=72)


# =========================================================
# Update (PATCH)
# =========================================================
class UserUpdateRequest(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=8, max_length=72)
    primary_mobile: Optional[str] = None
    role_id: Optional[int] = None
