import json

from fastapi import Request

from app.database import get_connection


def record_event(
    request: Request | None,
    action: str,
    *,
    user_id: int | None = None,
    username: str | None = None,
    resource_type: str | None = None,
    resource_id: str | int | None = None,
    result: str = "success",
    details: dict | None = None,
) -> None:

    """Write an audit event. Callers must never pass credentials or tokens."""
    client = request.client.host if request and request.client else None
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO audit_logs
                (user_id, username, action, resource_type, resource_id,
                 result, details, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                username,
                action[:100],
                resource_type[:50] if resource_type else None,
                str(resource_id)[:100] if resource_id is not None else None,
                result,
                json.dumps(details, ensure_ascii=False) if details else None,
                client,
            ),
        )
