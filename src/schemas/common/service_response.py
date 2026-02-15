from pydantic import BaseModel, ConfigDict
from typing import Generic, TypeVar, Optional, Any
from datetime import datetime, timezone
from src.utils.context import get_request_id

T = TypeVar("T")

class ServiceResponse(BaseModel, Generic[T]):
    success: bool
    message: Optional[str] = None
    status: int
    errors: Optional[Any] = None 
    timestamp: datetime
    request_id: str
    data: Optional[T] = None

    # Modern Pydantic v2 configuration
    model_config = ConfigDict(from_attributes=True)

def create_response(
    data: Optional[T] = None,
    message: Optional[str] = None,
    is_error: bool = False,
    errors: Optional[Any] = None,
    status_code: Optional[int] = None,
) -> dict:  # We return a dict to allow field popping
    
    # 1. Create the model to validate data
    response_obj = ServiceResponse(
        success=not is_error,
        message=message,
        status=status_code if status_code is not None else (-1 if is_error else 0),
        timestamp=datetime.now(timezone.utc),
        request_id=get_request_id(),
        errors=errors,
        data=data
    )

    # 2. Convert to dictionary
    response_dict = response_obj.model_dump()

    # 3. Apply your "No null errors" rule
    if not is_error and errors is None:
        response_dict.pop("errors", None)

    return response_dict