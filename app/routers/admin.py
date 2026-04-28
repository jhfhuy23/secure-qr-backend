from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.report import AdminReportsResponse, ReviewRequest, ReviewResponse
from app.repositories.report_repo import ReportRepository
from app.repositories.blacklist_repo import BlacklistRepository
from app.utils.url_normalizer import extract_domain
from app.security.dependencies import require_admin
from app.database import get_db
from app.utils.api_error import AppException
from app.utils.error_codes import ErrorCode
router = APIRouter()



@router.get("/admin/reports", response_model=AdminReportsResponse)
async def get_pending_reports(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin),
):
    repo   = ReportRepository(db)
    items, total = await repo.get_pending()
    return {"total": total, "items": items}


@router.post("/admin/reports/{report_id}/review", response_model=ReviewResponse)
async def review_report(
    report_id: int,
    body: ReviewRequest,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin),
):
    report_repo    = ReportRepository(db)
    blacklist_repo = BlacklistRepository(db)

    report = await report_repo.get_by_id(report_id)
    if not report:
         raise AppException(
            status_code=404,
            error_code=ErrorCode.REPORT_NOT_FOUND,
            message=f"Report with ID {report_id} was not found.",
            field="report_id",
        )

    if report.status != "pending":
        raise AppException(
            status_code=400,
            error_code=ErrorCode.REPORT_ALREADY_REVIEWED,
            message="This report has already been reviewed.",
            field="report_id",
        )

    if body.action == "confirmed":
        if not body.threat_type or body.severity is None:
              raise AppException(
                status_code=422,
                error_code=ErrorCode.REVIEW_MISSING_FIELDS,
                message="threat_type and severity are required when confirming a report.",
                field="threat_type",
            )
        # Promote to blacklist only if not already present
        existing = await blacklist_repo.find_by_hash(report.url_hash)
        if existing is None:
            from app.schemas.blacklist import BlacklistAddRequest
            blacklist_body = BlacklistAddRequest(
                url=report.url,
                threat_type=body.threat_type,
                severity=body.severity,
                source="user_report",
                notes=body.notes,
            )
            domain = extract_domain(report.url)
            await blacklist_repo.create(
                url=report.url,
                url_hash=report.url_hash,
                domain=domain,
                body=blacklist_body,
            )
        await report_repo.update_status(report_id, "confirmed")
        return {"message": "Report confirmed. URL added to blacklist."}

    # action == "dismissed"
    await report_repo.update_status(report_id, "dismissed")
    return {"message": "Report dismissed."}