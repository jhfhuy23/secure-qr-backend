from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.security.jwt_handler import create_access_token
from app.config import settings
from app.utils.api_error import AppException
from app.utils.error_codes import ErrorCode

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"


@router.post("/admin/login", response_model=LoginResponse)
async def admin_login(body: LoginRequest):
    if body.username != settings.ADMIN_USERNAME or \
       body.password != settings.ADMIN_PASSWORD:
        raise AppException(
            status_code=401,
            error_code=ErrorCode.INVALID_CREDENTIALS,
            message="Invalid username or password.",
        )
    token = create_access_token(role="admin")
    return {"access_token": token, "token_type": "bearer"}