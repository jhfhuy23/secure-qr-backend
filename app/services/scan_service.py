from sqlalchemy.ext.asyncio import AsyncSession
from datetime import date

from app.schemas.scan import ScanResultRequest
from app.repositories.scanned_url_repo import ScannedUrlRepository
from app.repositories.blacklist_repo import BlacklistRepository
from app.utils.url_normalizer import normalize_url, hash_url, extract_domain
from app.utils.logger import logger


class ScanService:

    def __init__(self, db: AsyncSession):
        self.scan_repo      = ScannedUrlRepository(db)
        self.blacklist_repo = BlacklistRepository(db)

    async def store(self, body: ScanResultRequest) -> dict:
        # Step 1 — normalize and hash
        normalized = normalize_url(body.raw_url)
        url_hash   = hash_url(normalized)
        domain     = extract_domain(body.raw_url)

        # Step 2 — blacklist cross-check
        blacklist_hit   = await self.blacklist_repo.find_active_by_hash(url_hash)
        was_blacklisted = blacklist_hit is not None

        # Step 3 — auto-blacklist if UNSAFE and not already present (idempotent)
        if body.safety_label == "UNSAFE" and not was_blacklisted:
            existing = await self.blacklist_repo.find_by_hash(url_hash)
            if existing is None:
                await self.blacklist_repo.create_from_detection(
                    url=normalized,
                    url_hash=url_hash,
                    domain=domain,
                )
                logger.info(f"Auto-blacklisted url_hash={url_hash} domain={domain}")
            was_blacklisted = True

        # Step 4 — persist scan record
        scan = await self.scan_repo.create(
            device_id=body.device_id,
            raw_url=body.raw_url,
            url_hash=url_hash,
            domain=domain,
            safety_score=body.safety_score,
            safety_label=body.safety_label,
            was_blacklisted=was_blacklisted,
            threat_type=body.threat_type,
        )

        return scan

    async def get_history(
        self,
        device_id: str,
        page: int,
        limit: int,
        label: str | None,
    ) -> dict:
        items, total = await self.scan_repo.get_by_device(device_id, page, limit, label)
        return {
            "total": total,
            "page": page,
            "limit": limit,
            "items": items,
        }

    async def get_statistics(self, from_date: date, to_date: date) -> dict:
        return await self.scan_repo.get_statistics(from_date, to_date)