from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import date

from app.models.scanned_url import ScannedUrl


class ScannedUrlRepository:

    def __init__(self, db: AsyncSession):   #constructor
        self.db = db

    async def create(
        self,
        device_id:       str,
        raw_url:         str,
        url_hash:        str,
        domain:          str,
        safety_score:    int,
        safety_label:    str,
        was_blacklisted: bool,
        threat_type:     str | None,
    ) -> dict:
        record = ScannedUrl(
            device_id=device_id,
            raw_url=raw_url,
            url_hash=url_hash,
            domain=domain,
            safety_score=safety_score,
            safety_label=safety_label,
            was_blacklisted=was_blacklisted,
            threat_type=threat_type,
        )
        self.db.add(record)
        await self.db.flush()  #Take all recent changes in the session and send the corresponding SQL to the database.
        await self.db.refresh(record)   #refreshing the record object here with values added in case of auto addin fileds the db (id..)

        # id → scan_id mapping (decided in Step 3)
        return {
            "scan_id":         record.id,
            "url_hash":        record.url_hash,
            "domain":          record.domain,
            "safety_score":    record.safety_score,
            "safety_label":    record.safety_label,
            "was_blacklisted": record.was_blacklisted,
            "scanned_at":      record.scanned_at,
        }

    async def get_by_device(
        self,
        device_id: str,
        page:      int,
        limit:     int,
        label:     str | None,
    ) -> tuple[list, int]:
        stmt = (
            select(ScannedUrl) #give me * from the table but rows as scannedurl objects , so each row is a single object with attrinutes , not multiple coulomns for row  like if we specified it (select(scannedurl.id,scannedurl.domain))
            .where(ScannedUrl.device_id == device_id)
            .order_by(ScannedUrl.scanned_at.desc())
        )
        if label:
            stmt = stmt.where(ScannedUrl.safety_label == label.upper())

        # total count
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total      = (await self.db.execute(count_stmt)).scalar() #scalar to make the couloumns form result:arry of [(row1,),(row2,)..] from db.execute , to single array of objects[row1,row2..]

        # paginated rows
        stmt   = stmt.offset((page - 1) * limit).limit(limit)
        result = await self.db.execute(stmt)
        rows   = result.scalars().all()
     
        # id → scan_id mapping on every row
        items = [
            {
                "scan_id":         row.id,
                "domain":          row.domain,
                "safety_label":    row.safety_label,
                "safety_score":    row.safety_score,
                "was_blacklisted": row.was_blacklisted,
                "scanned_at":      row.scanned_at,
            }
            for row in rows
        ]
        return items, total

    async def get_statistics(self, from_date: date, to_date: date) -> dict:
        # Count per safety_label
        stmt = (
            select(ScannedUrl.safety_label, func.count(ScannedUrl.id).label("count"))
            .where(ScannedUrl.scanned_at >= from_date)
            .where(ScannedUrl.scanned_at <= to_date)
            .group_by(ScannedUrl.safety_label)
        )
        result = await self.db.execute(stmt)
        rows   = result.all()
        counts = {row.safety_label: row.count for row in rows}
        total  = sum(counts.values())

        # Blacklist hits
        bl_stmt = (
            select(func.count(ScannedUrl.id))
            .where(ScannedUrl.scanned_at >= from_date)
            .where(ScannedUrl.scanned_at <= to_date)
            .where(ScannedUrl.was_blacklisted == True)
        )
        blacklist_hits = (await self.db.execute(bl_stmt)).scalar()

        # Top threat types — now a simple GROUP BY on a single column
        threat_stmt = (
            select(ScannedUrl.threat_type, func.count(ScannedUrl.id).label("count"))
            .where(ScannedUrl.scanned_at >= from_date)
            .where(ScannedUrl.scanned_at <= to_date)
            .where(ScannedUrl.threat_type != None)
            .group_by(ScannedUrl.threat_type)
            .order_by(func.count(ScannedUrl.id).desc())
            .limit(5)
        )
        threat_result    = await self.db.execute(threat_stmt)
        top_threat_types = [
            {"type": row.threat_type, "count": row.count}
            for row in threat_result.all()
        ]

        return {
            "period":           {"from": str(from_date), "to": str(to_date)},
            "total_scans":      total,
            "safe":             counts.get("SAFE", 0), #get function will give the value of safe field in the dictionary counts
            "suspicious":       counts.get("SUSPICIOUS", 0),
            "unsafe":           counts.get("UNSAFE", 0),
            "blacklist_hits":   blacklist_hits,
            "top_threat_types": top_threat_types,
        }