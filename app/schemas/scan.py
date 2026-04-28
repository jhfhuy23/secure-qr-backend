from pydantic import BaseModel, field_validator
from typing import List, Optional
from datetime import datetime


class ScanResultRequest(BaseModel):
    device_id: str
    raw_url: str
    safety_score: int
    safety_label: str
    threat_type: str

    @field_validator("raw_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if len(v) > 2048:
            raise ValueError("URL exceeds maximum length of 2048 characters")
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must begin with http:// or https://")
        return v

    @field_validator("device_id")
    @classmethod
    def validate_device_id(cls, v: str) -> str:
        if not v.isalnum() or not (8 <= len(v) <= 64):
            raise ValueError("device_id must be alphanumeric, 8-64 characters")
        return v

    @field_validator("safety_score")
    @classmethod
    def validate_score(cls, v: int) -> int:
        if not (0 <= v <= 100):
            raise ValueError("safety_score must be between 0 and 100")
        return v

    @field_validator("safety_label")
    @classmethod
    def validate_label(cls, v: str) -> str:
        allowed = {"SAFE", "SUSPICIOUS", "UNSAFE"}
        if v.upper() not in allowed:
            raise ValueError(f"safety_label must be one of: {allowed}")
        return v.upper()


class ScanResultResponse(BaseModel):
    scan_id: int
    url_hash: str
    domain: str
    safety_score: int
    safety_label: str
    was_blacklisted: bool
    scanned_at: datetime

    class Config:
        from_attributes = True


class ScanHistoryItem(BaseModel):
    scan_id: int
    domain: str
    safety_label: str
    safety_score: int
    was_blacklisted: bool
    scanned_at: datetime

    class Config:
        from_attributes = True


class ScanHistoryResponse(BaseModel):
    total: int
    page: int
    limit: int
    items: List[ScanHistoryItem]