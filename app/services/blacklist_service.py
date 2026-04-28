from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.blacklist import BlacklistAddRequest , BlacklistCheckRequest, blacklistFetchRequest
from app.repositories.blacklist_repo import BlacklistRepository
from app.utils.url_normalizer import normalize_url, hash_url, extract_domain


class BlacklistService:

    def __init__(self, db: AsyncSession):
        self.repo = BlacklistRepository(db)

    async def check(self, url: BlacklistCheckRequest) -> dict:

        normalized = normalize_url(url.url)
        url_hash   = hash_url(normalized)
        entry      = await self.repo.find_active_by_hash(url_hash)

        if entry:
            return {
                "is_blacklisted": True,
                "threat_type":    entry.threat_type,
                "severity":       entry.severity,
            }
        return {
            "is_blacklisted": False,
            "threat_type":    None,
            "severity":       None,
        }

    async def add(self, body: BlacklistAddRequest) -> dict:
        normalized = normalize_url(body.url)
        url_hash   = hash_url(normalized)
        domain     = extract_domain(body.url)

        # Idempotent: if already exists reactivate and update, else create
        existing = await self.repo.find_by_hash(url_hash)
        if existing:
            await self.repo.reactivate(url_hash, body)
            return {
                "id":       existing.id,
                "url_hash": url_hash,
                "domain":   None,
                "message":  "Entry updated and reactivated",
            }

        entry = await self.repo.create(normalized, url_hash, domain, body)
        return {
            "id":       entry.id,
            "url_hash": url_hash,
            "domain":   entry.domain,
            "message":  "URL added to blacklist",
        }
      
    async def deactivate(self, url_hash: str) -> bool:
        exist=await self.repo.soft_delete(url_hash)
        if not exist:
            return False
        return True

    async def get_paginated(
        self,
        page: int,
        limit: int,
        threat_type: str | None,
        since: str | None,
    ) -> dict:
        items, total = await self.repo.paginate(page, limit, threat_type, since)
        return {
            "total": total,
            "page":  page,
            "limit": limit,
            "items": items,
        }
    
    async def fetch_by_url(self, body: blacklistFetchRequest)-> dict | None:
     normalized = normalize_url(body.url)
     url_hash = hash_url(normalized)
     return await self.repo.find_full_by_hash(url_hash)
     