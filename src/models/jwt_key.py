# src/models/jwt_key.py
from sqlalchemy import Column, BigInteger, Integer
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.declarative import declarative_base
from .base import BaseEntity


class JwtKeyTable(BaseEntity):
    """
    Database table for JWT keys.
    Stores a singleton row containing:
      - current key
      - previous key
    The keys column is a JSONB array of Key dicts.
    """
    __tablename__ = "jwt_keys"
    __table_args__ = {"schema": "auth"}

    id = Column(Integer, primary_key=True, default=1)
    keys = Column(JSONB, nullable=False)  # list of Key dicts
    version = Column(BigInteger, nullable=False, default=1)
