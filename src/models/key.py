# src/schemas/jwt_key.py
from pydantic import BaseModel
from typing import List, Literal
from datetime import datetime

class Key(BaseModel):
    kid: str
    publicKey: str
    encryptedPrivateKey: str
    status: Literal["CURRENT", "PREVIOUS"]
    expiresAt: datetime

class JwtKeys(BaseModel):
    """
    keys: list containing max 2 elements: previous and current.
    """
    keys: List[Key]
    version: int = 1
