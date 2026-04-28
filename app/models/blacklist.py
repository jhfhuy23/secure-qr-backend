from sqlalchemy import (
    BigInteger, Boolean, Column, SmallInteger,
    String, Text, TIMESTAMP
)
from sqlalchemy.sql import func
from app.database import Base


class BlacklistedUrl(Base):
    __tablename__ = "blacklisted_urls"

    id                = Column(BigInteger, primary_key=True, autoincrement=True)
    url               = Column(Text, nullable=False)
    url_hash          = Column(String(64), nullable=False, unique=True)
    domain            = Column(String(253), nullable=False)
    threat_type       = Column(String(50), nullable=False)
    severity          = Column(SmallInteger, nullable=False, default=5)
    source            = Column(String(50), nullable=False)
    is_active         = Column(Boolean, nullable=False, default=True)
    added_at          = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    last_confirmed_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    notes             = Column(Text, nullable=True)