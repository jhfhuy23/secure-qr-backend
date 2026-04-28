from jose import jwt, JWTError
from datetime import datetime, timedelta
from fastapi import HTTPException
from app.config import settings
from app.utils.api_error import AppException
from app.utils.error_codes import ErrorCode

ALGORITHM  = "HS256"
EXPIRE_MIN = 60


def create_access_token(role: str) -> str:
    payload = {
        "role": role,
        "exp":  datetime.utcnow() + timedelta(minutes=EXPIRE_MIN), #exp is standard field in jwt  payloads tht represent expiration time , and tht is hndled in jwt.decode funtion , if 0 it raise jwt error
    }#exp store a number represnt number of seconds since Jan 1, 1970 +3600 seconds(1hour) to producin secondes from 1970 to expiring  time
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
      raise AppException(
            status_code=401,
            error_code=ErrorCode.UNAUTHORIZED,
            message="Invalid or expired token.",
        )