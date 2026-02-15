from sqlalchemy import Column, Integer, String, ForeignKey, UniqueConstraint, Index
from sqlalchemy.orm import relationship
from .base import BaseEntity
# Ensure you import the central Base from your database config
from src.config.database import Base 

class UserOAuthProvider(BaseEntity):
    __tablename__ = "user_oauth_providers"
    __table_args__ = (
        UniqueConstraint("provider", "provider_user_id", name="uk_provider_provider_user_id"),
        Index("idx_user_oauth_user_id", "user_id"),
        Index("idx_user_oauth_provider", "provider"),
        Index("idx_user_oauth_provider_user_id", "provider_user_id"),
        {"schema": "auth"}
    )

    user_id = Column(
        Integer, 
        ForeignKey("auth.users.id", ondelete="CASCADE"), 
        nullable=False
    )
    
    provider = Column(String(50), nullable=False) # 'google', 'github'

    provider_user_id = Column(String(100), nullable=False)
    # backref/back_populates depends on what you named the relationship in User model
    user = relationship("User", backref="oauth_providers", lazy="select")