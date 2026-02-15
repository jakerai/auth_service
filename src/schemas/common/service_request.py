from pydantic import BaseModel, root_validator, ValidationError
from typing import Generic, TypeVar, Optional, Type

T = TypeVar("T")

class ServiceRequest(BaseModel, Generic[T]):
    payload: T

    @root_validator(pre=True)
    def check_payload_exists(cls, values):
        if "payload" not in values or values["payload"] is None:
            raise ValueError("Payload is required")
        return values

    @classmethod
    def of(cls: Type["ServiceRequest[T]"], payload: T) -> "ServiceRequest[T]":
        return cls(payload=payload)
