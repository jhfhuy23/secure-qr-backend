from pydantic import BaseModel, field_validator
from typing import List, Optional
from datetime import datetime


class blacklistFetchRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if len(v) > 2048:
            raise ValueError("URL exceeds maximum length of 2048 characters")
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must begin with http:// or https://")
        return v

class BlacklistDesactivateRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if len(v) > 2048:
            raise ValueError("URL exceeds maximum length of 2048 characters")
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must begin with http:// or https://")
        return v
    
class BlacklistCheckRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if len(v) > 2048:
            raise ValueError("URL exceeds maximum length of 2048 characters")
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must begin with http:// or https://")
        return v


class BlacklistCheckResponse(BaseModel):
    is_blacklisted: bool
    threat_type: Optional[str]
    severity: Optional[int]


class BlacklistAddRequest(BaseModel):
    url: str
    threat_type: str
    severity: int
    source: str
    notes: Optional[str] = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if len(v) > 2048:
            raise ValueError("URL exceeds maximum length of 2048 characters")
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must begin with http:// or https://")
        return v

    @field_validator("threat_type")
    @classmethod
    def validate_threat_type(cls, v: str) -> str:
        allowed = {"PHISHING", "MALWARE", "SCAM", "REDIRECT"}
        if v.upper() not in allowed:
            raise ValueError(f"threat_type must be one of: {allowed}")
        return v.upper()

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: int) -> int:
        if not (1 <= v <= 10):
            raise ValueError("severity must be between 1 and 10")
        return v

    @field_validator("source")
    @classmethod
    def validate_source(cls, v: str) -> str:
        allowed = {"manual", "google_safe_browsing", "user_report", "detection_engine"}
        if v.lower() not in allowed:
            raise ValueError(f"source must be one of: {allowed}")
        return v.lower()


class BlacklistAddResponse(BaseModel):
    id: int
    url_hash: str
    domain: Optional[str] = None
    message: str


class BlacklistListItem(BaseModel):
    url_hash: str
    domain: str
    threat_type: str
    severity: int
    last_confirmed_at: datetime

    class Config:
        from_attributes = True


class BlacklistListResponse(BaseModel):
    total: int
    page: int
    limit: int
    items: List[BlacklistListItem]