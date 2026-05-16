from sqlalchemy import BigInteger, Column, String, TIMESTAMP
from sqlalchemy.sql import func
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id         = Column(BigInteger, primary_key=True, autoincrement=True)
    name       = Column(String(100), nullable=False)
    email      = Column(String(255), nullable=False, unique=True)
    password   = Column(String(255), nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())