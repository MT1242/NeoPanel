from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.database import get_connection


def configured_timezone() -> ZoneInfo:
    with get_connection() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = 'timezone'").fetchone()
    name = row["value"] if row else "Asia/Bangkok"
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError:
        return ZoneInfo("Asia/Bangkok")


def format_datetime(value: str | None) -> str:
    if not value:
        return "—"
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(configured_timezone()).strftime("%d/%m/%Y %H:%M")
    except (TypeError, ValueError):
        return str(value)
