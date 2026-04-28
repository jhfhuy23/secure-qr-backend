from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.security.jwt_handler import decode_token
from app.utils.api_error import AppException
from app.utils.error_codes import ErrorCode

bearer_scheme = HTTPBearer()


async def require_admin(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> dict:
    payload = decode_token(credentials.credentials)
    if payload.get("role") != "admin":
         raise AppException(
            status_code=403,
            error_code=ErrorCode.FORBIDDEN,
            message="Admin privileges required.",
        )
    return payload