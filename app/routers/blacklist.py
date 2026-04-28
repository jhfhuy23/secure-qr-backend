from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.blacklist import (
    BlacklistCheckRequest, BlacklistCheckResponse,
    BlacklistAddRequest, BlacklistAddResponse,
    BlacklistListResponse,BlacklistDesactivateRequest,blacklistFetchRequest
)
from app.services.blacklist_service import BlacklistService
from app.repositories.blacklist_repo import BlacklistRepository
from app.security.rate_limiter import limiter
from app.security.dependencies import require_admin
from app.database import get_db
from app.utils import url_normalizer
from app.utils.api_error import AppException
from app.utils.error_codes import ErrorCode

router = APIRouter()


@router.post("/blacklist/check", response_model=BlacklistCheckResponse)
@limiter.limit("60/minute")
async def check_blacklist(
    request: Request,
    body: BlacklistCheckRequest,
    db: AsyncSession = Depends(get_db),
):
    service = BlacklistService(db)
    return await service.check(body.url)


@router.get("/blacklist", response_model=BlacklistListResponse)
@limiter.limit("10/minute")
async def list_blacklist(
    request: Request,
    page: int = 1,
    limit: int = 100,
    threat_type: str | None = None,
    since: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    service = BlacklistService(db)
    return await service.get_paginated(page, limit, threat_type, since)


@router.post("/blacklist", response_model=BlacklistAddResponse, status_code=201)
@limiter.limit("10/minute")
async def add_to_blacklist(
    request: Request,
    body: BlacklistAddRequest,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin),
):
    service = BlacklistService(db)
    return await service.add(body)


@router.delete("/blacklist/{url_hash}")
@limiter.limit("10/minute")
async def remove_from_blacklist(
    request: Request,
    url_hash: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin),
):
    service = BlacklistService(db)
    found=await service.deactivate(url_hash)
    if not found :
        raise AppException(
            status_code=404,
            error_code=ErrorCode.BLACKLIST_ENTRY_NOT_FOUND,
            message="No blacklist entry found for the given URL hash.",
            field="url_hash",
        )
    return {"message": "Blacklist entry deactivated successfully"}

@router.delete("/blacklist")
@limiter.limit("10/minute")
async def delete_by_url(
    request: Request,
    body: BlacklistDesactivateRequest,   
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin)                   #same as above but with raw url
    ):
    
    normalized = url_normalizer.normalize_url(body.url)
    url_hash = url_normalizer.hash_url(normalized)
    service = BlacklistService(db)
    found=await service.deactivate(url_hash)
    if not found:
        raise AppException(
            status_code=404,
            error_code=ErrorCode.BLACKLIST_ENTRY_NOT_FOUND,
            message="No blacklist entry found for the given URL.",
            field="url",
        )
    return {"message": "Blacklist entry deactivated successfully"}


@router.post("/blacklist/detail")
@limiter.limit("10/minute")
async def fetch_from_blacklist(
    request: Request,
    body: blacklistFetchRequest,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin)
):
    service=BlacklistService(db)
    row= await service.fetch_by_url(body)
    if row is None:
          raise AppException(
            status_code=404,
            error_code=ErrorCode.BLACKLIST_ENTRY_NOT_FOUND,
            message="No blacklist entry found for the given URL.",
            field="url",
        )
    return row