from jose import jwt, JWTError
from datetime import datetime, timedelta
from app.config import settings
from app.utils.error_codes import ErrorCode

ALGORITHM  = "HS256"
EXPIRE_MIN = 60


def create_access_token(user_id: int, email: str) -> str:
    """Creates a JWT token for a regular user."""
    payload = {
        "role":    "user",
        "user_id": user_id,
        "email":   email,
        "exp":     datetime.utcnow() + timedelta(minutes=EXPIRE_MIN),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=ALGORITHM)


def create_admin_token() -> str:
    """Creates a JWT token for admin."""
    payload = {
        "role": "admin",
        "exp":  datetime.utcnow() + timedelta(minutes=EXPIRE_MIN),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    from app.utils.api_error import AppException
    try:
        return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise AppException(
            status_code=401,
            error_code=ErrorCode.UNAUTHORIZED,
            message="Invalid or expired token.",
        )