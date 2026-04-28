from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import date

from app.schemas.report import StatisticsResponse
from app.services.scan_service import ScanService
from app.database import get_db
from app.security.rate_limiter import limiter
router = APIRouter()


@router.get("/statistics", response_model=StatisticsResponse)
@limiter.limit("15/min")
async def get_statistics(
    request: Request,
    from_date: date = None,
    to_date: date = None,
    db: AsyncSession = Depends(get_db),
):
    # Default to current month if no dates provided
    today = date.today()
    if from_date is None:
        from_date = today.replace(day=1)
    if to_date is None:
        to_date = today

    service = ScanService(db)
    return await service.get_statistics(from_date, to_date)