from sqlalchemy import Column, Integer, String, ForeignKey, UniqueConstraint, Index
from sqlalchemy.orm import relationship
from .base import BaseEntity

class OAuthProvider(BaseEntity):
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

    user = relationship("User", back_populates="oauth_accounts", lazy="selectin")