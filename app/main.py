
import re
import secrets
import sqlite3
import os
import time
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pwdlib import PasswordHash
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.audit import record_event
from app.database import get_connection
from app.security import accessible_website_ids, get_csrf_token, has_permission, valid_csrf
from app.system_ops import OperationError, run_operation
from app.time_utils import format_datetime

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
SECRET_FILE = PROJECT_DIR / "data" / "session_secret"

if not SECRET_FILE.is_file():
    raise RuntimeError(
        "Thiếu data/session_secret. Hãy tạo khóa session trước khi chạy NeoPanel."
    )

SESSION_SECRET = SECRET_FILE.read_text().strip()

# Require at least 64 hex characters (256-bit entropy) — matches what install.sh
# generates via: openssl rand -hex 32
if len(SESSION_SECRET) < 64 or not all(c in "0123456789abcdefABCDEF" for c in SESSION_SECRET):
    raise RuntimeError(
        "Khóa session không hợp lệ. Hãy tạo lại bằng: openssl rand -hex 32 > data/session_secret"
    )

app = FastAPI(
    title="NeoPanel",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject security headers on every HTTP response."""

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        if os.environ.get("NEOPANEL_COOKIE_SECURE", "0").strip() == "1":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


# Middleware stack is LIFO: SecurityHeaders runs outermost.
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="neopanel_session",
    max_age=3600,
    same_site="lax",
    https_only=os.environ.get("NEOPANEL_COOKIE_SECURE", "0").strip() == "1",
)

app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "static"),
    name="static",
)

templates = Jinja2Templates(directory=BASE_DIR / "templates")
templates.env.filters["datetime_vi"] = format_datetime
password_hasher = PasswordHash.recommended()


@app.on_event("startup")
def initialize_database():
    from app.database import init_db

    init_db()
    with get_connection() as conn:
        interrupted = conn.execute("SELECT id, kind, resource_type, resource_id FROM jobs WHERE status IN ('queued', 'running')").fetchall()
        conn.execute("UPDATE jobs SET status = 'failed', error = 'Tác vụ bị gián đoạn khi NeoPanel khởi động lại.', finished_at = CURRENT_TIMESTAMP WHERE status IN ('queued', 'running')")
        for job in interrupted:
            if job["kind"] == "website_create" and job["resource_id"]:
                conn.execute("UPDATE websites SET status = 'failed' WHERE id = ?", (job["resource_id"],))
            elif job["kind"] == "certificate_issue" and job["resource_id"]:
                conn.execute("UPDATE ssl_certificates SET status = 'failed', last_error = 'Tác vụ bị gián đoạn khi NeoPanel khởi động lại.' WHERE id = ?", (job["resource_id"],))
            elif job["kind"] in {"website_backup", "database_backup", "website_backup_scheduled"} and job["resource_id"]:
                conn.execute("UPDATE backups SET status = 'failed', error = 'Tác vụ bị gián đoạn khi NeoPanel khởi động lại.' WHERE id = ?", (job["resource_id"],))


def valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False

    labels = domain.split(".")

    if len(labels) < 2:
        return False

    return all(
        len(label) <= 63
        and re.fullmatch(
            r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?",
            label,
        )
        for label in labels
    )


def find_active_user(username: str):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT id, username, password_hash, role, is_active, session_version
            FROM users
            WHERE username = ? AND is_active = 1
            LIMIT 1
            """,
            (username,),
        ).fetchone()


def get_websites(request: Request | None = None):
    with get_connection() as conn:
        websites = conn.execute(
            """
            SELECT id, domain, document_root, php_version, status, created_at
            FROM websites
            ORDER BY id DESC
            """
        ).fetchall()
    scope = accessible_website_ids(request) if request else None
    if scope is not None:
        websites = [website for website in websites if website["id"] in scope]
    return websites


def active_session_user(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    now = int(time.time())
    last_activity = int(request.session.get("last_activity", now))
    if now - last_activity > 3600:
        request.session.clear()
        return None
    with get_connection() as conn:
        user = conn.execute("SELECT id, username, role, is_active, session_version FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or not user["is_active"] or request.session.get("session_version") != user["session_version"]:
        request.session.clear()
        return None
    request.session["username"] = user["username"]
    request.session["role"] = user["role"]
    request.session["session_version"] = user["session_version"]
    request.session["last_activity"] = now
    return user


def login_is_limited(username: str, request: Request) -> bool:
    ip_address = request.client.host if request.client else ""
    with get_connection() as conn:
        # Block if username has >= 5 failed attempts in 15 minutes.
        by_user = conn.execute(
            """
            SELECT COUNT(*) AS attempts FROM login_attempts
            WHERE attempted_at >= datetime('now', '-15 minutes')
              AND succeeded = 0 AND username = ?
            """,
            (username,),
        ).fetchone()
        # Block if IP has >= 20 failed attempts regardless of username.
        by_ip = conn.execute(
            """
            SELECT COUNT(*) AS attempts FROM login_attempts
            WHERE attempted_at >= datetime('now', '-15 minutes')
              AND succeeded = 0 AND ip_address = ?
            """,
            (ip_address,),
        ).fetchone()
    return by_user["attempts"] >= 5 or by_ip["attempts"] >= 20


def record_login_attempt(username: str, request: Request, succeeded: bool) -> None:
    ip_address = request.client.host if request.client else None
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO login_attempts (username, ip_address, succeeded) VALUES (?, ?, ?)",
            (username[:50], ip_address, int(succeeded)),
        )


def execute_website_job(job_id: int) -> None:
    with get_connection() as conn:
        job = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        website = conn.execute(
            "SELECT * FROM websites WHERE id = ?", (job["resource_id"],)
        ).fetchone() if job else None
        if not job or not website:
            return
        conn.execute(
            "UPDATE jobs SET status = 'running', progress = 10, started_at = CURRENT_TIMESTAMP WHERE id = ?",
            (job_id,),
        )

    try:
        if job["kind"] == "website_create":
            from app.modules import website_aliases

            run_operation(
                "website_create",
                {
                    "domain": website["domain"],
                    "document_root": website["document_root"],
                    "php_version": website["php_version"],
                    "aliases": website_aliases(website["id"]),
                    "webroot": website["public_dir"],
                },
            )
            final_status = "active"
        elif job["kind"] == "website_delete":
            run_operation("website_delete", {"domain": website["domain"]})
            final_status = None
        else:
            operation = "website_disable" if job["kind"] == "website_disable" else "website_enable"
            run_operation(operation, {"domain": website["domain"]})
            final_status = "disabled" if job["kind"] == "website_disable" else "active"

        with get_connection() as conn:
            if job["kind"] == "website_delete":
                conn.execute("DELETE FROM websites WHERE id = ?", (website["id"],))
            else:
                conn.execute("UPDATE websites SET status = ? WHERE id = ?", (final_status, website["id"]))
            conn.execute(
                "UPDATE jobs SET status = 'succeeded', progress = 100, message = 'Hoàn tất', finished_at = CURRENT_TIMESTAMP WHERE id = ?",
                (job_id,),
            )
        record_event(
            None,
            job["kind"],
            user_id=job["requested_by"],
            resource_type="website",
            resource_id=website["id"],
        )
    except Exception as exc:
        safe_error = str(exc)[:240] if isinstance(exc, OperationError) else "Tác vụ lỗi nội bộ."
        with get_connection() as conn:
            conn.execute(
                "UPDATE websites SET status = 'failed' WHERE id = ? AND ? = 'website_create'",
                (website["id"], job["kind"]),
            )
            conn.execute(
                "UPDATE jobs SET status = 'failed', error = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?",
                (safe_error, job_id),
            )
        record_event(
            None,
            job["kind"],
            user_id=job["requested_by"],
            resource_type="website",
            resource_id=website["id"],
            result="failure",
            details={"error": safe_error},
        )


def render_dashboard(
    request: Request,
    error: str | None = None,
    success: str | None = None,
    status_code: int = 200,
):
    websites = get_websites(request)
    try:
        php_versions = run_operation("php_versions").get("versions", [])
    except OperationError:
        php_versions = []
    from app.modules import NAV_SHELL, collect_metrics, host_os_label, role_label

    nav_shell = NAV_SHELL
    os_name = host_os_label()
    role_name = role_label(request.session.get("role"))
    try:
        server_metrics = collect_metrics()
    except (OSError, ValueError):
        server_metrics = []

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "title": "Tổng quan",
            "description": "Quản lý website, dịch vụ hosting và tình trạng máy chủ.",
            "username": request.session.get("username", ""),
            "csrf_token": get_csrf_token(request),
            "can_manage_websites": has_permission(request, "websites.update"),
            "can_delete_websites": has_permission(request, "websites.delete"),
            "websites": websites,
            "website_count": len(websites),
            "php_versions": php_versions,
            "server_metrics": server_metrics,
            "error": error,
            "success": success,
            "nav_shell": nav_shell,
            "active_module": "overview",
            "role_label": role_name,
            "os_label": os_name,
        },
        status_code=status_code,
    )


@app.get("/health")
def health_check(request: Request):
    # Return minimal response — do not expose app name or version to unauthenticated callers.
    return {"status": "ok"}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "csrf_token": get_csrf_token(request),
            "error": None,
        },
    )


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request):
    form = await request.form()

    csrf_token = str(form.get("csrf_token", ""))
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))

    if not valid_csrf(request, csrf_token):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "csrf_token": get_csrf_token(request),
                "error": "Phiên đăng nhập không hợp lệ. Vui lòng tải lại trang.",
            },
            status_code=403,
        )

    if login_is_limited(username, request):
        record_login_attempt(username, request, False)
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "csrf_token": get_csrf_token(request),
                "error": "Đăng nhập tạm thời bị khóa do có quá nhiều lần thử. Hãy thử lại sau 15 phút.",
            },
            status_code=429,
        )

    user = None
    if username and len(username) <= 50 and password:
        user = find_active_user(username)

    password_ok = False
    if user:
        try:
            password_ok = password_hasher.verify(
                password,
                user["password_hash"],
            )
        except Exception:
            password_ok = False

    if not user or not password_ok:
        record_login_attempt(username, request, False)
        record_event(request, "login", username=username, result="failure")
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "csrf_token": get_csrf_token(request),
                "error": "Tên đăng nhập hoặc mật khẩu không đúng.",
            },
            status_code=401,
        )

    request.session.clear()
    request.session["user_id"] = user["id"]
    request.session["username"] = user["username"]
    request.session["role"] = user["role"]
    request.session["session_version"] = user["session_version"]
    request.session["csrf_token"] = secrets.token_urlsafe(32)
    request.session["last_activity"] = int(time.time())
    record_login_attempt(username, request, True)
    record_event(request, "login", user_id=user["id"], username=user["username"])

    return RedirectResponse("/", status_code=303)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    user = active_session_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not has_permission(request, "websites.read"):
        return HTMLResponse("Bạn không có quyền truy cập dashboard.", status_code=403)

    return render_dashboard(request)


@app.post("/websites", response_class=HTMLResponse)
async def create_website(request: Request, background_tasks: BackgroundTasks):
    user = active_session_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not has_permission(request, "websites.create"):
        return HTMLResponse("Bạn không có quyền tạo website.", status_code=403)

    form = await request.form()

    csrf_token = str(form.get("csrf_token", ""))
    domain = str(form.get("domain", "")).strip().lower().rstrip(".")
    php_version = str(form.get("php_version", "")).strip()

    if not valid_csrf(request, csrf_token):
        return render_dashboard(
            request,
            error="Phiên làm việc không hợp lệ. Vui lòng tải lại trang.",
            status_code=403,
        )

    if not valid_domain(domain):
        return render_dashboard(
            request,
            error="Tên miền không hợp lệ. Ví dụ: example.com.",
            status_code=400,
        )

    try:
        available_versions = run_operation("php_versions").get("versions", [])
    except OperationError:
        available_versions = []
    if php_version not in available_versions:
        return render_dashboard(
            request,
            error="Hãy chọn phiên bản PHP-FPM đã cài đặt. Nếu danh sách trống, cần cài helper Ubuntu và PHP-FPM trước.",
            status_code=400,
        )

    document_root = f"/var/www/neopanel/{domain}"

    try:
        with get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO websites
                    (domain, document_root, php_version, status)
                VALUES (?, ?, ?, ?)
                """,
                (domain, document_root, php_version, "pending"),
            )
            website_id = cursor.lastrowid
            conn.execute(
                "INSERT INTO domains (website_id, domain, is_primary) VALUES (?, ?, 1)",
                (website_id, domain),
            )
            cursor = conn.execute(
                "INSERT INTO jobs (kind, resource_type, resource_id, requested_by, message) VALUES (?, 'website', ?, ?, ?)",
                ("website_create", website_id, request.session.get("user_id"), "Đang chờ tạo website"),
            )
            job_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        return render_dashboard(
            request,
            error="Tên miền này đã tồn tại trong NeoPanel.",
            status_code=400,
        )

    record_event(
        request,
        "website_create_requested",
        user_id=request.session.get("user_id"),
        username=request.session.get("username"),
        resource_type="website",
        resource_id=website_id,
    )
    background_tasks.add_task(execute_website_job, job_id)
    return RedirectResponse("/", status_code=303)


@app.post("/websites/{website_id}/toggle")
async def toggle_website(website_id: int, request: Request, background_tasks: BackgroundTasks):
    user = active_session_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not has_permission(request, "websites.update"):
        return HTMLResponse("Bạn không có quyền thay đổi website.", status_code=403)

    form = await request.form()
    if not valid_csrf(request, str(form.get("csrf_token", ""))):
        return render_dashboard(request, error="Phiên làm việc không hợp lệ.", status_code=403)

    with get_connection() as conn:
        website = conn.execute("SELECT id, status FROM websites WHERE id = ?", (website_id,)).fetchone()
        if not website:
            return render_dashboard(request, error="Không tìm thấy website.", status_code=404)
        kind = "website_enable" if website["status"] == "disabled" else "website_disable"
        cursor = conn.execute(
            "INSERT INTO jobs (kind, resource_type, resource_id, requested_by, message) VALUES (?, 'website', ?, ?, ?)",
            (kind, website_id, request.session.get("user_id"), "Đang chờ cập nhật Nginx"),
        )
        job_id = cursor.lastrowid

    background_tasks.add_task(execute_website_job, job_id)
    record_event(
        request,
        kind + "_requested",
        user_id=request.session.get("user_id"),
        username=request.session.get("username"),
        resource_type="website",
        resource_id=website_id,
    )
    return RedirectResponse("/", status_code=303)


@app.post("/websites/{website_id}/delete")
async def delete_website(website_id: int, request: Request, background_tasks: BackgroundTasks):
    user = active_session_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not has_permission(request, "websites.delete"):
        return HTMLResponse("Bạn không có quyền xóa cấu hình website.", status_code=403)
    form = await request.form()
    if not valid_csrf(request, str(form.get("csrf_token", ""))):
        return render_dashboard(request, error="Phiên làm việc không hợp lệ.", status_code=403)
    with get_connection() as conn:
        website = conn.execute("SELECT id, domain FROM websites WHERE id = ?", (website_id,)).fetchone()
        if not website or str(form.get("confirm_domain", "")) != website["domain"]:
            return render_dashboard(request, error="Tên xác nhận không khớp; website chưa bị xóa.", status_code=400)
        cursor = conn.execute(
            "INSERT INTO jobs (kind, resource_type, resource_id, requested_by, message) VALUES ('website_delete', 'website', ?, ?, 'Đang gỡ cấu hình Nginx; tệp và database được giữ lại')",
            (website_id, user["id"]),
        )
        job_id = cursor.lastrowid
    record_event(request, "website_delete_requested", user_id=user["id"], username=user["username"], resource_type="website", resource_id=website_id, result="warning")
    background_tasks.add_task(execute_website_job, job_id)
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
async def logout(request: Request):
    form = await request.form()
    csrf_token = str(form.get("csrf_token", ""))

    if not valid_csrf(request, csrf_token):
        return HTMLResponse(
            "Yêu cầu không hợp lệ. Hãy quay lại trang quản trị và thử lại.",
            status_code=403,
        )

    record_event(
        request,
        "logout",
        user_id=request.session.get("user_id"),
        username=request.session.get("username"),
    )
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


from app.modules import router as modules_router

app.include_router(modules_router)
