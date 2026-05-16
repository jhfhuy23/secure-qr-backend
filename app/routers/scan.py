from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.scan import ScanResultRequest, ScanResultResponse, ScanHistoryResponse
from app.services.scan_service import ScanService
from app.security.rate_limiter import limiter
from app.security.dependencies import require_user
from app.utils.url_normalizer import is_private_target
from app.utils.logger import logger
from app.utils.api_error import AppException
from app.utils.error_codes import ErrorCode
from app.database import get_db

router = APIRouter()


@router.post("/scan/result", response_model=ScanResultResponse)
@limiter.limit("30/minute")
async def store_scan_result(
    request: Request,
    body: ScanResultRequest,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_user),
):
    if is_private_target(body.raw_url):
        logger.warning(f"SSRF probe detected device_id={body.device_id} url={body.raw_url}")
        raise AppException(
            status_code=400,
            error_code=ErrorCode.INVALID_URL_TARGET,
            message="URL resolves to a private or reserved address.",
            field="raw_url",
        )
    service = ScanService(db)
    return await service.store(body, user_id=user["user_id"])


@router.get("/scan/history", response_model=ScanHistoryResponse)
async def get_scan_history(
    request: Request,
    page:  int = 1,
    limit: int = 20,
    label: str | None = None,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_user),
):
    service = ScanService(db)
    return await service.get_history(
        user_id=user["user_id"],
        page=page,
        limit=limit,
        label=label,
    )