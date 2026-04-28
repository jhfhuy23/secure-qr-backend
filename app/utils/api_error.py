from pydantic import BaseModel
from datetime import datetime, timezone
from typing import Optional
from fastapi import HTTPException

from app.utils.error_codes import ErrorCode


class ApiErrorDetail(BaseModel):
    code:       str
    message:    str
    field:      Optional[str]  = None
    request_id: Optional[str]  = None
    timestamp:  str


class ApiErrorResponse(BaseModel):
    error: ApiErrorDetail


class AppException(HTTPException):
    """
    Raise this instead of HTTPException everywhere in the app.
    Carries a structured ErrorCode + optional field context.
    """
    def __init__(
        self,
        status_code: int,
        error_code:  ErrorCode,
        message:     str,
        field:       Optional[str] = None,
    ):
        super().__init__(status_code=status_code, detail=message)
        self.error_code = error_code
        self.field      = field


def build_error_response(
    error_code:  ErrorCode,
    message:     str,
    field:       Optional[str] = None,
    request_id:  Optional[str] = None,
) -> dict:
    return {
        "error": {
            "code":       error_code.value,
            "message":    message,
            "field":      field,
            "request_id": request_id,
            "timestamp":  datetime.now(timezone.utc).isoformat(),
        }
    }