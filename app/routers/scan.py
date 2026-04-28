from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.scan import ScanResultRequest, ScanResultResponse, ScanHistoryResponse
from app.services.scan_service import ScanService
from app.security.rate_limiter import limiter
from app.utils.url_normalizer import is_private_target
from app.utils.logger import logger
from app.database import get_db
from app.config import settings
from app.utils.api_error import AppException
from app.utils.error_codes import ErrorCode
router = APIRouter()


@router.post("/scan/result", response_model=ScanResultResponse)
@limiter.limit("30/minute")
async def store_scan_result(
    request: Request,
    body: ScanResultRequest,
    db: AsyncSession = Depends(get_db),
):
    if  not settings.TEST_MODE and  is_private_target(body.raw_url):
        logger.warning(
            f"SSRF probe detected device_id={body.device_id} url={body.raw_url}"
        )
        raise AppException(
            status_code=400,
            error_code=ErrorCode.INVALID_URL_TARGET,
            message="URL resolves to a private or reserved address.",
            field="raw_url",
        )
    service = ScanService(db)
    return await service.store(body)


@router.get("/scan/history", response_model=ScanHistoryResponse)
async def get_scan_history(
    request: Request,
    device_id: str,
    page: int = 1,
    limit: int = 20,
    label: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    service = ScanService(db)
    return await service.get_history(device_id, page, limit, label)