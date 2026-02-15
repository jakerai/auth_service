from pydantic import BaseModel, Field
from typing import Optional

class ApiKeyCreateRequest(BaseModel):
    expires_in_days: int = Field(
        ..., 
        ge=1, 
        le=1825, 
        description="Number of days before the key expires (1-1825)"
    )
    
    user_id: Optional[int] = Field(
        None, 
        description="Optional user ID"
    )