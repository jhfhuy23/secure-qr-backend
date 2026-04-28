from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.report import ReportRequest, ReportResponse
from app.repositories.report_repo import ReportRepository
from app.utils.url_normalizer import normalize_url, hash_url
from app.security.rate_limiter import limiter
from app.database import get_db

router = APIRouter()


@router.post("/report", response_model=ReportResponse, status_code=202)
@limiter.limit("5/minute")
async def submit_report(
    request: Request,
    body: ReportRequest,
    db: AsyncSession = Depends(get_db),
):
    normalized = normalize_url(body.url)
    url_hash   = hash_url(normalized)

    repo   = ReportRepository(db)
    report = await repo.create(
        device_id=body.device_id,
        url=normalized,
        url_hash=url_hash,
        reason=body.reason,
    )
    return {
        "report_id": report.id,
        "status":    report.status,
        "message":   "Report received and queued for review.",
    }