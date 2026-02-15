from sqlalchemy import Column, Integer, String, DateTime, JSON, Index
# Ensure you import the central Base from your database config
from src.config.database import Base 
from datetime import datetime, timezone
from enum import Enum as PyEnum

class ActionEnum(str, PyEnum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    PWD_CHANGE = "password_change"
    PERM_CHANGE = "permission_change"

class ResourceEnum(str, PyEnum):
    USER = "user"
    ROLE = "role"
    PERMISSION = "permission"
    API_KEY = "api_key"

class Activity(Base):
    __tablename__ = "activity"
    __table_args__ = (
        Index("ix_activity_user_resource", "user_id", "resource_type", "resource_id"),
        {"schema": "auth"}
    )
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Who did it
    user_id = Column(Integer, nullable=True, index=True) 
    
    # What was done - UPDATED to String
    action = Column(String(50), nullable=False, index=True)
    
    # What was affected - UPDATED to String
    resource_type = Column(String(50), nullable=True, index=True)
    resource_id = Column(String(100), nullable=True, index=True) 
    
    # Technical details
    payload = Column(JSON, nullable=True) 
    
    # Metadata
    remarks = Column(String(500), nullable=True)
    ip = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    
    # Timing
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))