from sqlalchemy import Column, Integer, DateTime
from datetime import datetime, timezone
from src.config.database import Base

class BaseEntity(Base):
    __abstract__ = True

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    created_by = Column(Integer, nullable=True)
    modified_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                         onupdate=lambda: datetime.now(timezone.utc))
    modified_by = Column(Integer, nullable=True)
