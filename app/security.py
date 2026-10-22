import secrets

from fastapi import Request

from app.database import get_connection


def get_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def valid_csrf(request: Request, submitted_token: str) -> bool:
    stored_token = request.session.get("csrf_token")
    return bool(
        stored_token
        and submitted_token
        and secrets.compare_digest(stored_token, submitted_token)
    )


def has_permission(request: Request, permission: str) -> bool:
    role = request.session.get("role")
    if role == "admin":
        role = "super_admin"
    if role == "super_admin":
        return True
    if not role:
        return False
    with get_connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM role_permissions WHERE role_name = ? AND permission_name = ?",
            (role, permission),
        ).fetchone()
    return bool(row)


def accessible_website_ids(request: Request | None):
    if not request:
        return None
    if request.session.get("role") != "website_manager":
        return None
    with get_connection() as conn:
        rows = conn.execute("SELECT website_id FROM user_websites WHERE user_id = ?", (request.session.get("user_id"),)).fetchall()
    return {row["website_id"] for row in rows}


def accessible_website_ids(request: Request):
    if request.session.get("role") != "website_manager":
        return None
    with get_connection() as conn:
        rows = conn.execute("SELECT website_id FROM user_websites WHERE user_id = ?", (request.session.get("user_id"),)).fetchall()
    return {row["website_id"] for row in rows}
