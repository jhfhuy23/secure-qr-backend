from pydantic import BaseModel, field_validator
from typing import Optional
from datetime import datetime


class ReportRequest(BaseModel):
    device_id: str
    url: str
    reason: Optional[str] = None

    @field_validator("url")
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


class ReportResponse(BaseModel):
    report_id: int
    status: str
    message: str


class AdminReportItem(BaseModel):
    report_id: int
    url_hash: str
    domain: str
    reason: Optional[str]
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class AdminReportsResponse(BaseModel):
    total: int
    items: list[AdminReportItem]


class ReviewRequest(BaseModel):
    action: str
    threat_type: Optional[str] = None
    severity: Optional[int] = None
    notes: Optional[str] = None

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        allowed = {"confirmed", "dismissed"}
        if v.lower() not in allowed:
            raise ValueError(f"action must be one of: {allowed}")
        return v.lower()

    @field_validator("threat_type")
    @classmethod
    def validate_threat_type(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        allowed = {"PHISHING", "MALWARE", "SCAM", "REDIRECT"}
        if v.upper() not in allowed:
            raise ValueError(f"threat_type must be one of: {allowed}")
        return v.upper()

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: Optional[int]) -> Optional[int]:
        if v is None:
            return v
        if not (1 <= v <= 10):
            raise ValueError("severity must be between 1 and 10")
        return v


class ReviewResponse(BaseModel):
    message: str


class StatisticsResponse(BaseModel):
    period: dict
    total_scans: int
    safe: int
    suspicious: int
    unsafe: int
    blacklist_hits: int
    top_threat_types: list