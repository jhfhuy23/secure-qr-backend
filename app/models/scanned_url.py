from sqlalchemy import (
    BigInteger, Boolean, Column, SmallInteger,
    String, Text, TIMESTAMP
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.sql import func
from app.database import Base
 
 
class ScannedUrl(Base):
    __tablename__ = "scanned_urls"
 
    id             = Column(BigInteger, primary_key=True, autoincrement=True)
    device_id      = Column(String(64), nullable=False)
    raw_url        = Column(Text, nullable=False)
    url_hash       = Column(String(64), nullable=False)
    domain         = Column(String(253), nullable=False)
    safety_score   = Column(SmallInteger, nullable=False)
    safety_label   = Column(String(20), nullable=False)
    was_blacklisted = Column(Boolean, nullable=False, default=False)
    threat_type   = Column( String(50),  nullable=True)
    scanned_at     = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())