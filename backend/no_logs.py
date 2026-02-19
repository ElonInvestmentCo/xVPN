import time
import asyncio
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from backend.database import SessionLocal
from backend.models import ServerLog

NO_LOGS_RETENTION_MINUTES = 5
PURGE_INTERVAL_SECONDS = 60


def create_minimal_log(
    db: Session,
    event_type: str,
    server_id: str | None = None,
    duration_seconds: int | None = None,
    bytes_transferred: int | None = None,
    protocol: str | None = None,
    region: str | None = None,
) -> ServerLog:
    anonymized_region = None
    if region and len(region) >= 2:
        anonymized_region = region[:2].upper()

    purge_at = datetime.now(timezone.utc) + timedelta(minutes=NO_LOGS_RETENTION_MINUTES)

    now = datetime.now(timezone.utc)
    rounded_timestamp = now.replace(minute=0, second=0, microsecond=0)

    log = ServerLog(
        event_type=event_type,
        server_id=None,
        timestamp=rounded_timestamp,
        duration_seconds=duration_seconds,
        bytes_transferred=bytes_transferred,
        protocol=protocol,
        anonymized_region=anonymized_region,
        purge_after=purge_at,
        is_purged=False,
        no_logs_compliant=True,
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


def purge_expired_logs(db: Session) -> int:
    now = datetime.now(timezone.utc)
    expired = db.query(ServerLog).filter(
        ServerLog.purge_after <= now,
        ServerLog.is_purged == False,
    ).all()

    count = 0
    for log in expired:
        db.delete(log)
        count += 1

    if count > 0:
        db.commit()

    return count


async def auto_purge_loop():
    while True:
        try:
            await asyncio.sleep(PURGE_INTERVAL_SECONDS)
            db = SessionLocal()
            try:
                purged = purge_expired_logs(db)
            finally:
                db.close()
        except asyncio.CancelledError:
            break
        except Exception:
            pass


def get_no_logs_policy() -> dict:
    return {
        "policy": "Strict No-Logs",
        "version": "1.0",
        "details": {
            "connection_logs": "Never stored",
            "activity_logs": "Never stored",
            "ip_addresses": "Never recorded",
            "dns_queries": "Never logged",
            "browsing_history": "Never tracked",
            "session_data": "Auto-purged after {} minutes".format(NO_LOGS_RETENTION_MINUTES),
            "server_ids": "Stripped from all records",
            "timestamps": "Rounded to nearest hour in aggregates",
            "data_retention": "{} minutes maximum".format(NO_LOGS_RETENTION_MINUTES),
        },
        "what_we_store": [
            "Anonymized aggregate bandwidth (region-level only)",
            "Session duration (for billing, auto-purged)",
            "Account credentials (hashed, never plaintext)",
        ],
        "what_we_never_store": [
            "Your real IP address",
            "Websites you visit",
            "DNS queries",
            "Connection timestamps with user identity",
            "Traffic content or metadata",
            "Device identifiers",
            "Server-specific connection logs",
        ],
        "audited": True,
        "jurisdiction": "Privacy-friendly jurisdiction",
    }
