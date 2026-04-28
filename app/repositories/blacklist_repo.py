from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime

from app.models.blacklist import BlacklistedUrl
from app.schemas.blacklist import BlacklistAddRequest


class BlacklistRepository:

    def __init__(self, db: AsyncSession):
        self.db = db

    async def find_active_by_hash(self, url_hash: str) -> BlacklistedUrl | None:
        stmt = (
            select(BlacklistedUrl)
            .where(BlacklistedUrl.url_hash == url_hash)
            .where(BlacklistedUrl.is_active == True)
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def find_by_hash(self, url_hash: str) -> BlacklistedUrl | None:
        stmt   = select(BlacklistedUrl).where(BlacklistedUrl.url_hash == url_hash)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def create(
        self,
        url:      str,
        url_hash: str,
        domain:   str,
        body:     BlacklistAddRequest,
    ) -> BlacklistedUrl:
        entry = BlacklistedUrl(
            url=url,
            url_hash=url_hash,
            domain=domain,
            threat_type=body.threat_type,
            severity=body.severity,
            source=body.source,
            notes=body.notes,
            is_active=True,
        )
        self.db.add(entry)
        await self.db.flush()
        await self.db.refresh(entry)
        return entry

    async def create_from_detection(
        self,
        url:         str,
        url_hash:    str,
        domain:      str,
        threat_type: str | None,
    ) -> BlacklistedUrl:
        """Called by scan_service when safety_label == UNSAFE."""
        entry = BlacklistedUrl(
            url=url,
            url_hash=url_hash,
            domain=domain,
            threat_type=threat_type or "MALWARE",
            severity=5,
            source="detection_engine",
            is_active=True,
        )
        self.db.add(entry)
        await self.db.flush()
        await self.db.refresh(entry)
        return entry

    async def reactivate(self, url_hash: str, body: BlacklistAddRequest) -> None:
        stmt   = select(BlacklistedUrl).where(BlacklistedUrl.url_hash == url_hash)
        result = await self.db.execute(stmt)
        entry  = result.scalar_one_or_none()
        if entry:
            entry.is_active         = True
            entry.threat_type       = body.threat_type
            entry.severity          = body.severity
            entry.source            = body.source
            entry.notes             = body.notes
            entry.last_confirmed_at = datetime.utcnow()
            await self.db.flush()

    async def soft_delete(self, url_hash: str) -> bool:
        stmt   = select(BlacklistedUrl).where(BlacklistedUrl.url_hash == url_hash)
        result = await self.db.execute(stmt)
        entry  = result.scalar_one_or_none()
        if entry is None:
            return False
        if entry:
            entry.is_active = False
            await self.db.flush()
            return True
        
        
    async def paginate(
        self,
        page:        int,
        limit:       int,
        threat_type: str | None,
        since:       str | None,
    ) -> tuple[list, int]:
        stmt = select(BlacklistedUrl).where(BlacklistedUrl.is_active == True)

        if threat_type:
            stmt = stmt.where(BlacklistedUrl.threat_type == threat_type)
        if since:
            stmt = stmt.where(
                BlacklistedUrl.last_confirmed_at >= datetime.fromisoformat(since)
            )

        # total count
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total      = (await self.db.execute(count_stmt)).scalar()

        # paginated rows
        stmt   = stmt.offset((page - 1) * limit).limit(limit)
        result = await self.db.execute(stmt)
        rows   = result.scalars().all()

        # Return hash + domain only — never raw URL (architecture requirement)
        items = [
            {
                "url_hash":          row.url_hash,
                "domain":            row.domain,
                "threat_type":       row.threat_type,
                "severity":          row.severity,
                "last_confirmed_at": row.last_confirmed_at,
            }
            for row in rows
        ]
        return items, total
    
    
    async def find_full_by_hash(self, hash: str) -> dict | None:
        sttmnt=select(BlacklistedUrl).where(BlacklistedUrl.url_hash==hash)
        res= await self.db.execute(sttmnt)
        entry=res.scalar_one_or_none()
        if entry is None:
            return None
        return {
            "url_hash":          entry.url_hash,
            "domain":            entry.domain,
            "threat_type":       entry.threat_type,
            "severity":          entry.severity,
            "source":            entry.source,
            "is_active":         entry.is_active,
            "added_at":          entry.added_at,
            "last_confirmed_at": entry.last_confirmed_at,
            "notes":             entry.notes,
        }
        return