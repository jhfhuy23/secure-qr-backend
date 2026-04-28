from sqlalchemy import (
    BigInteger, Column, String, Text, TIMESTAMP
)
from sqlalchemy.sql import func
from app.database import Base


class Report(Base):
    __tablename__ = "reports"

    id          = Column(BigInteger, primary_key=True, autoincrement=True)
    device_id   = Column(String(64), nullable=False)
    url         = Column(Text, nullable=False)
    url_hash    = Column(String(64), nullable=False)
    reason      = Column(Text, nullable=True)
    status      = Column(String(20), nullable=False, default="pending")
    created_at  = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    reviewed_at = Column(TIMESTAMP(timezone=True), nullable=True)