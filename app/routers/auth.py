import bcrypt
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.user import RegisterRequest, RegisterResponse, UserLoginRequest, UserLoginResponse
from app.repositories.user_repo import UserRepository
from app.security.jwt_handler import create_access_token, create_admin_token
from app.utils.api_error import AppException
from app.utils.error_codes import ErrorCode
from app.config import settings
from app.database import get_db
from pydantic import BaseModel

router = APIRouter()


# ── Admin login ───────────────────────────────────────────────────────────────
class AdminLoginRequest(BaseModel):
    username: str
    password: str


class AdminLoginResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"


@router.post("/admin/login", response_model=AdminLoginResponse)
async def admin_login(body: AdminLoginRequest):
    if body.username != settings.ADMIN_USERNAME or \
       body.password != settings.ADMIN_PASSWORD:
        raise AppException(
            status_code=401,
            error_code=ErrorCode.INVALID_CREDENTIALS,
            message="Invalid username or password.",
        )
    token = create_admin_token()
    return {"access_token": token, "token_type": "bearer"}


# ── User register ─────────────────────────────────────────────────────────────
@router.post("/auth/register", response_model=RegisterResponse, status_code=201)
async def register(
    body: RegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    repo     = UserRepository(db)
    existing = await repo.find_by_email(body.email)
    if existing:
        raise AppException(
            status_code=409,
            error_code=ErrorCode.EMAIL_ALREADY_REGISTERED,
            message="An account with this email already exists.",
            field="email",
        )
    hashed = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    user   = await repo.create(name=body.name, email=body.email, hashed_password=hashed)
    return {
        "user_id": user.id,
        "name":    user.name,
        "email":   user.email,
        "message": "Account created successfully.",
    }


# ── User login ────────────────────────────────────────────────────────────────
@router.post("/auth/login", response_model=UserLoginResponse)
async def user_login(
    body: UserLoginRequest,
    db: AsyncSession = Depends(get_db),
):
    repo = UserRepository(db)
    user = await repo.find_by_email(body.email)
    if not user:
        raise AppException(
            status_code=401,
            error_code=ErrorCode.USER_NOT_FOUND,
            message="No account found with this email.",
            field="email",
        )
    if not bcrypt.checkpw(body.password.encode(), user.password.encode()):
        raise AppException(
            status_code=401,
            error_code=ErrorCode.WRONG_PASSWORD,
            message="Incorrect password.",
            field="password",
        )
    token = create_access_token(user_id=user.id, email=user.email)
    return {
        "access_token": token,
        "token_type":   "bearer",
        "user_id":      user.id,
        "name":         user.name,
        "email":        user.email,
    }