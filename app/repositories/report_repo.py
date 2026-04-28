from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime

from app.models.report import Report


class ReportRepository:

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(
        self,
        device_id: str,
        url: str,
        url_hash: str,
        reason: str | None,
    ) -> Report:
        report = Report(
            device_id=device_id,
            url=url,
            url_hash=url_hash,
            reason=reason,
            status="pending",
        )
        self.db.add(report)
        await self.db.flush()
        await self.db.refresh(report)
        return report

    async def get_pending(self) -> tuple[list, int]:
        stmt = (
            select(Report)
            .where(Report.status == "pending")
            .order_by(Report.created_at.desc())
        )
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total      = (await self.db.execute(count_stmt)).scalar()

        result = await self.db.execute(stmt)
        rows   = result.scalars().all()

        items = [
            {
                "report_id":  row.id,
                "url_hash":   row.url_hash,
                "domain":     row.url,       # domain extracted at service layer
                "reason":     row.reason,
                "status":     row.status,
                "created_at": row.created_at,
            }
            for row in rows
        ]
        return items, total

    async def get_by_id(self, report_id: int) -> Report | None:
        stmt   = select(Report).where(Report.id == report_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def update_status(
        self,
        report_id: int,
        status: str,
    ) -> None:
        stmt   = select(Report).where(Report.id == report_id)
        result = await self.db.execute(stmt)
        report = result.scalar_one_or_none()
        if report:
            report.status      = status
            report.reviewed_at = datetime.utcnow()
            await self.db.flush()