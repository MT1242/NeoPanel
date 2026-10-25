import ipaddress
import json
import base64
import os
import re
import secrets
import sqlite3
import shutil
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pwdlib import PasswordHash

from app.audit import record_event
from app.database import get_connection
from app.security import accessible_website_ids, get_csrf_token, has_permission, valid_csrf
from app.system_ops import OperationError, run_operation
from app.time_utils import format_datetime

router = APIRouter()
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=BASE_DIR / "templates")
templates.env.filters["datetime_vi"] = format_datetime
password_hasher = PasswordHash.recommended()
FILE_ACTIONS = {"upload_file", "create_directory", "create_file", "save_file", "delete_file", "rename_file", "move_file", "copy_file", "archive_file", "extract_file", "set_webroot", "bulk_archive", "bulk_delete", "bulk_move", "bulk_copy"}
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
MODULES = {
    "domains": ("Tên miền", "Quản lý domain, subdomain và trạng thái DNS.", "domains.read"),
    "dns": ("Bản ghi DNS", "Quản lý bản ghi A, AAAA, CNAME, MX, TXT, NS cho từng tên miền.", "dns.read"),
    "databases": ("Cơ sở dữ liệu", "Quản lý MariaDB và người dùng database.", "databases.read"),
    "php": ("Phiên bản PHP", "Gán PHP-FPM cho website và sửa php.ini, php-fpm.conf của từng phiên bản.", "php.read"),
    "ssl": ("SSL/TLS", "Chứng chỉ, thời hạn và trạng thái HTTPS.", "ssl.read"),
    "files": ("Quản lý tệp", "Chỉ truy cập bên trong document root của website đã chọn.", "files.read"),
    "services": ("Máy chủ và dịch vụ", "Trạng thái dịch vụ được NeoPanel theo dõi.", "services.read"),
    "monitoring": ("Giám sát tài nguyên", "Số liệu trực tiếp từ máy chủ NeoPanel.", "monitoring.read"),
    "backups": ("Sao lưu và phục hồi", "Tạo, theo dõi và phục hồi bản sao lưu website.", "backups.read"),
    "logs": ("Nhật ký hoạt động", "Lịch sử đăng nhập và thao tác quản trị.", "logs.read"),
    "jobs": ("Hàng đợi tác vụ", "Theo dõi các thao tác hệ thống đang chạy và kết quả.", "jobs.read"),
    "users": ("Người dùng và phân quyền", "Quản lý tài khoản quản trị NeoPanel.", "users.read"),
    "settings": ("Cài đặt hệ thống", "Cấu hình cảnh báo và thông tin vận hành NeoPanel.", "settings.read"),
}
NAV_GROUPS = [
    ("Quản lý hosting", [("Website", "/", "websites"), ("Tên miền", "/modules/domains", "domains"), ("Bản ghi DNS", "/modules/dns", "dns"), ("Cơ sở dữ liệu", "/modules/databases", "databases"), ("Quản lý tệp", "/modules/files", "files"), ("Phiên bản PHP", "/modules/php", "php"), ("SSL/TLS", "/modules/ssl", "ssl")]),
    ("Vận hành hệ thống", [("Máy chủ và dịch vụ", "/modules/services", "services"), ("Giám sát tài nguyên", "/modules/monitoring", "monitoring"), ("Hàng đợi tác vụ", "/modules/jobs", "jobs"), ("Sao lưu và phục hồi", "/modules/backups", "backups"), ("Nhật ký hoạt động", "/modules/logs", "logs")]),
    ("Quản trị", [("Người dùng và phân quyền", "/modules/users", "users"), ("Cài đặt hệ thống", "/modules/settings", "settings")]),
]
NAV_ICONS = {
    "overview": "home",
    "websites": "globe",
    "domains": "globe",
    "dns": "globe",
    "databases": "database",
    "files": "folder",
    "php": "code",
    "ssl": "lock",
    "services": "server",
    "monitoring": "pulse",
    "jobs": "queue",
    "backups": "archive",
    "logs": "list",
    "users": "users",
    "settings": "settings",
}
NAV_SHELL = [
    {"kind": "link", "label": "Tổng quan", "href": "/", "icon": "home", "key": "overview"},
]
for _section_label, _links in NAV_GROUPS:
    NAV_SHELL.append({
        "kind": "section",
        "label": _section_label,
        "children": [
            {"label": _label, "href": _href, "key": _key, "icon": NAV_ICONS.get(_key, "folder")}
            for _label, _href, _key in _links
        ],
    })
ROLE_LABELS = {
    "admin": "Quản trị viên",
    "super_admin": "Quản trị viên",
    "hosting_admin": "Hosting Admin",
    "website_manager": "Website Manager",
    "read_only": "Chỉ xem",
}


def host_os_label():
    try:
        info = {}
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                info[key] = value.strip().strip('"')
        return info.get("PRETTY_NAME") or info.get("NAME") or "Linux"
    except OSError:
        return "Linux"


def role_label(role: str | None) -> str:
    return ROLE_LABELS.get(role or "", "Thành viên")


def file_type_label(path: Path, is_dir: bool) -> str:
    if is_dir:
        return "Thư mục"
    name = path.name.lower()
    if name in {".htaccess", ".htpasswd"}:
        return "text/plain"
    mapping = {
        ".php": "application/x-httpd-php",
        ".phtml": "application/x-httpd-php",
        ".html": "text/html",
        ".htm": "text/html",
        ".txt": "text/plain",
        ".md": "text/markdown",
        ".css": "text/css",
        ".js": "application/javascript",
        ".json": "application/json",
        ".xml": "application/xml",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".gif": "image/gif",
        ".svg": "image/svg+xml",
        ".webp": "image/webp",
        ".zip": "application/zip",
        ".gz": "application/gzip",
        ".tar": "application/x-tar",
        ".env": "text/plain",
        ".log": "text/plain",
        ".sql": "application/sql",
    }
    return mapping.get(path.suffix.lower(), "application/octet-stream")


def file_icon_kind(name: str, is_dir: bool) -> str:
    if is_dir:
        return "folder"
    lower = name.lower()
    if lower in {".htaccess", ".htpasswd"}:
        return "code"
    ext = Path(name).suffix.lower()
    if ext in {".php", ".phtml"}:
        return "php"
    if ext in {".html", ".htm"}:
        return "html"
    if ext in {".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp"}:
        return "image"
    if ext in {".zip", ".gz", ".tgz", ".tar"}:
        return "archive"
    if ext in {".js", ".css", ".json", ".xml", ".yml", ".yaml", ".env", ".sql"}:
        return "code"
    return "file"


def signed_in_user(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    with get_connection() as conn:
        user = conn.execute(
            "SELECT id, username, role, is_active, session_version FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    if not user or not user["is_active"] or request.session.get("session_version") != user["session_version"]:
        request.session.clear()
        return None
    now = int(time.time())
    if now - int(request.session.get("last_activity", now)) > 3600:
        request.session.clear()
        return None
    request.session["role"] = user["role"]
    request.session["session_version"] = user["session_version"]
    request.session["username"] = user["username"]
    request.session["last_activity"] = now
    return user


def website_choices(request: Request | None = None):
    with get_connection() as conn:
        rows = conn.execute("SELECT id, domain FROM websites ORDER BY domain").fetchall()
    scope = accessible_website_ids(request)
    if scope is not None:
        rows = [row for row in rows if row["id"] in scope]
    return [{"value": row["id"], "label": row["domain"]} for row in rows]


def website_in_scope(request: Request, website_id: int) -> bool:
    scope = accessible_website_ids(request)
    return scope is None or website_id in scope


def domains_valid(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    labels = value.rstrip(".").split(".")
    return len(labels) >= 2 and all(
        len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    )


def website_aliases(website_id: int) -> list[str]:
    """Alias (non-primary) domains of a website, as stored in the panel DB."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT domain FROM domains WHERE website_id = ? AND is_primary = 0 ORDER BY domain",
            (website_id,),
        ).fetchall()
    return [r["domain"] for r in rows]


def sync_zone(domain_id: int) -> dict:
    """Push all records of a domain to the helper, which rewrites the BIND zone."""
    with get_connection() as conn:
        domain = conn.execute("SELECT domain FROM domains WHERE id = ?", (domain_id,)).fetchone()
        records = conn.execute(
            "SELECT name, type, value, priority, ttl FROM dns_records WHERE domain_id = ? ORDER BY id",
            (domain_id,),
        ).fetchall()
    return run_operation("dns_zone_write", {"domain": domain["domain"], "records": [dict(r) for r in records]})


def validate_dns_record(rtype: str, name: str, value: str, priority, ttl):
    if rtype not in {"A", "AAAA", "CNAME", "MX", "TXT", "NS"}:
        raise ValueError("Loại bản ghi không hợp lệ.")
    if not re.fullmatch(r"@|\*|[A-Za-z0-9_*][A-Za-z0-9_.-]{0,252}", name):
        raise ValueError("Tên bản ghi không hợp lệ.")
    if not value or len(value) > 2000 or any(ord(c) < 32 for c in value):
        raise ValueError("Giá trị bản ghi không hợp lệ.")
    if rtype in {"A", "AAAA"}:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("Giá trị phải là địa chỉ IP hợp lệ.")
        if ip.version != (4 if rtype == "A" else 6):
            raise ValueError(f"Bản ghi {rtype} cần địa chỉ IPv{4 if rtype == 'A' else 6}.")
    elif rtype in {"CNAME", "NS", "MX"} and not domains_valid(value.rstrip(".")):
        raise ValueError("Giá trị phải là tên miền hợp lệ.")
    if rtype == "CNAME" and name == "@":
        raise ValueError("Không được đặt CNAME ở tên miền gốc (@).")
    if rtype == "MX":
        if priority is None or not 0 <= priority <= 65535:
            raise ValueError("MX cần độ ưu tiên từ 0 đến 65535.")
    else:
        priority = None
    if not 60 <= ttl <= 86400:
        raise ValueError("TTL phải từ 60 đến 86400 giây.")
    return priority


def get_module_data(module: str, request: Request | None = None):
    warning = None
    columns = []
    rows = []
    forms = []
    metrics = []
    notice = None
    row_ids = []
    row_actions = []
    schedule_rows = []
    schedule_ids = []
    file_icons = []
    file_website = None
    tree_dirs = []
    disk_used = "—"
    disk_total = "—"
    php_versions = []
    php_config_files = []
    selected_php_version = ""
    selected_php_file = ""
    php_edit = None
    websites = website_choices(request)
    scope = accessible_website_ids(request)

    if module == "domains":
        columns = ["Tên miền", "Website", "Vai trò", "DNS", "Kiểm tra lúc"]
        with get_connection() as conn:
            data = conn.execute(
                """SELECT d.*, w.domain AS website_domain FROM domains d
                   JOIN websites w ON w.id = d.website_id ORDER BY d.is_primary DESC, d.domain"""
            ).fetchall()
        if scope is not None:
            data = [r for r in data if r["website_id"] in scope]
        rows = [[r["domain"], r["website_domain"], "Chính" if r["is_primary"] else "Bí danh", r["dns_status"], format_datetime(r["checked_at"]) if r["checked_at"] else "Chưa kiểm tra"] for r in data]
        row_ids = [r["id"] for r in data]
        row_actions = [{"action": "check_dns", "label": "Kiểm tra DNS", "can_remove": not r["is_primary"]} for r in data]
        forms = [{"title": "Thêm domain", "action": "add_domain", "fields": [
            {"name": "domain", "label": "Tên miền", "placeholder": "blog.example.com"},
            {"name": "website_id", "label": "Website", "type": "select", "options": websites},
        ], "button": "Thêm domain"}]
        notice = "Kiểm tra DNS chỉ xác nhận khi NEOPANEL_PUBLIC_IP được cấu hình trên máy chủ."

    elif module == "dns":
        columns = ["Tên miền", "Tên", "Loại", "Giá trị", "Ưu tiên", "TTL"]
        with get_connection() as conn:
            zone_domains = conn.execute("SELECT id, domain, website_id FROM domains ORDER BY domain").fetchall()
            data = conn.execute(
                """SELECT r.*, d.domain AS zone, d.website_id FROM dns_records r
                   JOIN domains d ON d.id = r.domain_id ORDER BY d.domain, r.type, r.name"""
            ).fetchall()
        if scope is not None:
            zone_domains = [d for d in zone_domains if d["website_id"] in scope]
            data = [r for r in data if r["website_id"] in scope]
        rows = [[r["zone"], r["name"], r["type"], r["value"], r["priority"] if r["priority"] is not None else "—", r["ttl"]] for r in data]
        row_ids = [r["id"] for r in data]
        row_actions = [{"action": "delete_record", "label": "Xóa"} for _ in data]
        forms = [{"title": "Thêm bản ghi DNS", "action": "add_record", "fields": [
            {"name": "domain_id", "label": "Tên miền", "type": "select", "options": [{"value": d["id"], "label": d["domain"]} for d in zone_domains]},
            {"name": "name", "label": "Tên bản ghi (@ = gốc, www, mail...)", "placeholder": "@"},
            {"name": "type", "label": "Loại", "type": "select", "options": [{"value": t, "label": t} for t in ("A", "AAAA", "CNAME", "MX", "TXT", "NS")]},
            {"name": "value", "label": "Giá trị (IP, tên miền hoặc nội dung TXT)"},
            {"name": "priority", "label": "Độ ưu tiên (chỉ dành cho MX)", "type": "number", "placeholder": "10"},
            {"name": "ttl", "label": "TTL (giây)", "type": "number", "placeholder": "3600"},
        ], "button": "Thêm bản ghi"}]
        notice = "Bản ghi được ghi vào file zone BIND9 khi máy chủ đã cài BIND9 (sudo apt install bind9). Sau đó trỏ NS của tên miền về máy chủ này."

    elif module == "databases":
        columns = ["Database", "Tài khoản", "Website", "Máy chủ", "Trạng thái", "Ngày tạo"]
        with get_connection() as conn:
            data = conn.execute(
                """SELECT d.*, w.domain AS website_domain FROM hosting_databases d
                   LEFT JOIN websites w ON w.id = d.website_id WHERE d.status != 'deleted'
                   ORDER BY d.id DESC"""
            ).fetchall()
        if scope is not None:
            data = [r for r in data if r["website_id"] in scope]
        rows = [[r["name"], r["username"], r["website_domain"] or "—", r["host"], r["status"], format_datetime(r["created_at"])] for r in data]
        row_ids = [r["id"] for r in data]
        forms = [{"title": "Tạo database MariaDB", "action": "create_database", "fields": [
            {"name": "name", "label": "Tên database (chỉ chữ thường, số, dấu gạch dưới)"},
            {"name": "password", "label": "Mật khẩu (để trống = tự tạo ngẫu nhiên)", "type": "password"},
            {"name": "website_id", "label": "Gắn với website", "type": "select", "options": websites},
        ], "button": "Tạo database"}]
        notice = "Mật khẩu tự nhập hoặc tự tạo đều không được lưu trong SQLite. Mật khẩu ngẫu nhiên chỉ hiển thị một lần."
    elif module == "php":
        columns = ["Phiên bản", "PHP-FPM socket", "Trạng thái"]
        try:
            versions = run_operation("php_versions").get("versions", [])
            php_versions = versions
            rows = [[v, f"/run/php/php{v}-fpm.sock", "Đã cài đặt"] for v in versions]
            if not versions:
                notice = "Không tìm thấy PHP-FPM socket. Hãy cài phiên bản PHP-FPM trước."
            else:
                forms = [{"title": "Gán PHP cho website", "action": "assign_php", "fields": [
                    {"name": "website_id", "label": "Website", "type": "select", "options": websites},
                    {"name": "php_version", "label": "Phiên bản PHP-FPM", "type": "select", "options": [{"value": v, "label": f"PHP {v}"} for v in versions]},
                ], "button": "Áp dụng phiên bản"}]
                selected_php_version = (request.query_params.get("version") or "").strip() if request else ""
                selected_php_file = (request.query_params.get("file") or "").strip() if request else ""
                if selected_php_version and selected_php_version not in versions:
                    notice = "Phiên bản PHP không có trên máy chủ."
                    selected_php_version = ""
                    selected_php_file = ""
                if selected_php_version:
                    try:
                        listed = run_operation("php_config_list", {"version": selected_php_version})
                        php_config_files = listed.get("files", [])
                        if not selected_php_file:
                            selected_php_file = next((item["path"] for item in php_config_files if item["path"] == "fpm/php.ini"), php_config_files[0]["path"] if php_config_files else "")
                        if selected_php_file:
                            read = run_operation("php_config_read", {"version": selected_php_version, "path": selected_php_file})
                            label = next((item["label"] for item in php_config_files if item["path"] == selected_php_file), selected_php_file)
                            php_edit = {
                                "version": selected_php_version,
                                "path": selected_php_file,
                                "label": label,
                                "content": read.get("content", ""),
                                "exists": read.get("exists", True),
                            }
                    except OperationError as exc:
                        notice = str(exc)
        except OperationError as exc:
            notice = str(exc)

    elif module == "ssl":
        columns = ["Domain", "Website", "Nhà cấp", "Hết hạn", "Trạng thái"]
        with get_connection() as conn:
            data = conn.execute(
                """SELECT c.*, w.domain AS website_domain FROM ssl_certificates c
                   JOIN websites w ON w.id = c.website_id ORDER BY c.id DESC"""
            ).fetchall()
        if scope is not None:
            data = [r for r in data if r["website_id"] in scope]
        rows = [[r["domain"], r["website_domain"], r["issuer"] or "Let's Encrypt", format_datetime(r["expires_at"]) if r["expires_at"] else "—", r["status"]] for r in data]
        forms = [{"title": "Yêu cầu chứng chỉ Let's Encrypt", "action": "issue_certificate", "fields": [
            {"name": "website_id", "label": "Website", "type": "select", "options": websites},
            {"name": "email", "label": "Email nhận thông báo gia hạn", "type": "email"},
        ], "button": "Cấp chứng chỉ"}]
        notice = "Domain cần trỏ DNS đúng về máy chủ và cổng 80 phải truy cập được để xác minh HTTP-01."

    elif module == "services":
        columns = ["Dịch vụ", "Trạng thái"]
        names = ["neopanel", "nginx", "mariadb"]
        try:
            versions = run_operation("php_versions").get("versions", [])
            names.extend(f"php{v}-fpm" for v in versions)
            for name in names:
                try:
                    result = run_operation("service_status", {"name": name})
                    rows.append([name, result["status"]])
                except OperationError:
                    rows.append([name, "Không khả dụng"])
        except OperationError as exc:
            notice = str(exc)

    elif module == "monitoring":
        metrics = collect_metrics()
        columns = ["Chỉ số", "Giá trị"]
        rows = [[m["label"], m["value"]] for m in metrics]

    elif module == "backups":
        columns = ["Đối tượng", "Loại", "Dung lượng", "Trạng thái", "Tạo lúc"]
        with get_connection() as conn:
            data = conn.execute(
                """SELECT b.*, w.domain, d.name AS database_name FROM backups b
                   LEFT JOIN websites w ON w.id = b.website_id
                   LEFT JOIN hosting_databases d ON d.id = b.database_id
                   ORDER BY b.id DESC LIMIT 100"""
            ).fetchall()
        if scope is not None:
            data = [r for r in data if r["website_id"] in scope]
        rows = [[r["domain"] or r["database_name"] or "—", r["kind"], _format_bytes(r["size_bytes"]), r["status"], format_datetime(r["created_at"])] for r in data]
        row_ids = [r["id"] for r in data]
        row_actions = [{"action": "restore_backup", "label": "Phục hồi" if r["status"] == "completed" else "Chưa sẵn sàng"} for r in data]
        with get_connection() as conn:
            db_rows = conn.execute("SELECT id, name FROM hosting_databases WHERE status = 'active' ORDER BY name").fetchall()
        db_choices = [{"value": row["id"], "label": row["name"]} for row in db_rows]
        forms = [{"title": "Sao lưu website", "action": "create_backup", "fields": [
            {"name": "website_id", "label": "Website", "type": "select", "options": websites},
        ], "button": "Tạo bản sao lưu"}]
        forms.append({"title": "Sao lưu database", "action": "create_database_backup", "fields": [
            {"name": "database_id", "label": "Database", "type": "select", "options": db_choices},
        ], "button": "Sao lưu database"})
        forms.append({"title": "Lập lịch sao lưu website", "action": "create_schedule", "fields": [
            {"name": "website_id", "label": "Website", "type": "select", "options": websites},
            {"name": "frequency", "label": "Tần suất", "type": "select", "options": [
                {"value": "daily", "label": "Hàng ngày"}, {"value": "weekly", "label": "Hàng tuần"}, {"value": "monthly", "label": "Hàng tháng"},
            ]},
            {"name": "retention_days", "label": "Giữ bản sao (ngày)", "type": "number", "value": "30"},
        ], "button": "Tạo lịch"})
        with get_connection() as conn:
            schedules = conn.execute("""SELECT s.*, w.domain FROM backup_schedules s
                JOIN websites w ON w.id = s.website_id ORDER BY s.id DESC""").fetchall()
        if scope is not None:
            schedules = [item for item in schedules if item["website_id"] in scope]
        schedule_rows = [[item["domain"], item["frequency"], str(item["retention_days"]), "Đang bật" if item["enabled"] else "Đã tạm dừng", format_datetime(item["next_run_at"])] for item in schedules]
        schedule_ids = [item["id"] for item in schedules]
        notice = "Bản sao lưu được kiểm tra checksum và lưu ngoài document root tại /var/backups/neopanel. Lịch chạy cần cài timer theo hướng dẫn Ubuntu."

    elif module == "logs":
        columns = ["Thời gian", "Người dùng", "Hành động", "Đối tượng", "Kết quả", "Địa chỉ IP"]
        with get_connection() as conn:
            data = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200").fetchall()
        rows = [[format_datetime(r["created_at"]), r["username"] or "system", r["action"], f"{r['resource_type'] or ''} {r['resource_id'] or ''}".strip(), r["result"], r["ip_address"] or "—"] for r in data]

    elif module == "jobs":
        columns = ["Loại", "Đối tượng", "Trạng thái", "Tiến độ", "Thông tin", "Bắt đầu", "Hoàn tất"]
        with get_connection() as conn:
            data = conn.execute("""SELECT j.*, u.username FROM jobs j
                LEFT JOIN users u ON u.id = j.requested_by ORDER BY j.id DESC LIMIT 200""").fetchall()
        rows = [[r["kind"], f"{r['resource_type'] or ''} {r['resource_id'] or ''}".strip(), r["status"], f"{r['progress']}%", r["error"] or r["message"] or "—", format_datetime(r["started_at"]) if r["started_at"] else "—", format_datetime(r["finished_at"]) if r["finished_at"] else "—"] for r in data]

    elif module == "users":
        columns = ["Tên đăng nhập", "Vai trò", "Trạng thái", "Ngày tạo"]
        with get_connection() as conn:
            data = conn.execute("SELECT id, username, role, is_active, created_at FROM users ORDER BY id").fetchall()
        rows = [[r["username"], r["role"], "Hoạt động" if r["is_active"] else "Đã khóa", format_datetime(r["created_at"])] for r in data]
        row_ids = [r["id"] for r in data]
        row_actions = [{"action": "toggle_user", "label": "Khóa" if r["is_active"] else "Mở khóa"} for r in data]
        forms = [{"title": "Tạo tài khoản quản trị", "action": "create_user", "fields": [
            {"name": "username", "label": "Tên đăng nhập"},
            {"name": "password", "label": "Mật khẩu", "type": "password"},
            {"name": "role", "label": "Vai trò", "type": "select", "options": [
                {"value": "super_admin", "label": "Super Admin"},
                {"value": "hosting_admin", "label": "Hosting Admin"},
                {"value": "website_manager", "label": "Website Manager"},
                {"value": "read_only", "label": "Read-only"},
            ]},
            {"name": "website_ids", "label": "Website được phép quản lý (bắt buộc với Website Manager)", "type": "select", "multiple": True, "options": websites},
        ], "button": "Tạo tài khoản"}]

    elif module == "settings":
        columns = ["Cài đặt", "Giá trị"]
        with get_connection() as conn:
            data = conn.execute("SELECT key, value FROM settings ORDER BY key").fetchall()
        values = {r["key"]: r["value"] for r in data}
        for key, default in [("timezone", "Asia/Bangkok"), ("disk_warning_percent", "80"), ("disk_critical_percent", "90")]:
            values.setdefault(key, default)
        rows = [[key, value] for key, value in values.items()]
        forms = [{"title": "Cập nhật cài đặt", "action": "save_settings", "fields": [
            {"name": "timezone", "label": "Múi giờ", "value": values["timezone"]},
            {"name": "disk_warning_percent", "label": "Cảnh báo đĩa (%)", "type": "number", "value": values["disk_warning_percent"]},
            {"name": "disk_critical_percent", "label": "Ngưỡng nghiêm trọng (%)", "type": "number", "value": values["disk_critical_percent"]},
        ], "button": "Lưu cài đặt"}]

    elif module == "files":
        columns = ["Tên tệp / thư mục", "Kích thước", "Loại", "Chỉnh sửa lần cuối"]
        notice = None
        selected_website_id = 0
        current_path = ""
        public_dir = ""
        editing = bool(request and request.url.path.endswith("/files/edit"))
        if request:
            try:
                selected_website_id = int(request.query_params.get("website_id", "0"))
            except ValueError:
                selected_website_id = 0
            current_path = request.query_params.get("path", "").strip().strip("/")
        try:
            php_versions = run_operation("php_versions").get("versions", [])
        except OperationError:
            php_versions = []
        if not selected_website_id and len(websites) == 1:
            selected_website_id = int(websites[0]["value"])
        if selected_website_id and not editing:
            with get_connection() as conn:
                website = conn.execute(
                    "SELECT id, domain, document_root, public_dir, php_version, status FROM websites WHERE id = ?",
                    (selected_website_id,),
                ).fetchone()
            if scope is not None and selected_website_id not in scope:
                website = None
            if website:
                public_dir = website["public_dir"]
                file_website = dict(website)
                root = Path(website["document_root"]).resolve()
                current = (root / current_path).resolve() if current_path else root
                try:
                    usage = shutil.disk_usage(root if root.exists() else "/")
                    disk_used = _format_bytes(usage.used)
                    disk_total = _format_bytes(usage.total)
                except OSError:
                    disk_used, disk_total = "—", "—"
                try:
                    is_valid_dir = current.is_relative_to(root) and current.is_dir()
                except OSError:
                    is_valid_dir = None
                if is_valid_dir is None:
                    warning = "Không đủ quyền đọc document root. Hãy thêm user dịch vụ NeoPanel vào nhóm www-data rồi khởi động lại dịch vụ."
                elif is_valid_dir:
                    try:
                        entries = sorted(current.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower()))[:500]
                        rows = []
                        for entry in entries:
                            if not entry.resolve().is_relative_to(root):
                                continue
                            is_dir = entry.is_dir()
                            rel = str(entry.relative_to(root))
                            try:
                                stat = entry.stat()
                                size = "—" if is_dir else _format_bytes(stat.st_size)
                                mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%d/%m/%Y %H:%M")
                            except OSError:
                                size, mtime = "—", "—"
                            kind = file_type_label(entry, is_dir)
                            rows.append([entry.name, size, kind, mtime])
                            row_ids.append(rel)
                            file_icons.append(file_icon_kind(entry.name, is_dir))
                            row_actions.append({"action": "delete_file", "label": "Xóa"})
                            if is_dir:
                                tree_dirs.append({"name": entry.name, "path": rel})
                    except OSError:
                        warning = "Không đủ quyền đọc document root. Hãy thêm user dịch vụ NeoPanel vào nhóm www-data rồi khởi động lại dịch vụ."
                else:
                    warning = "Đường dẫn thư mục không hợp lệ hoặc không nằm trong document root."
            else:
                warning = "Hãy chọn một website hợp lệ."
        elif not selected_website_id:
            notice = "Chọn website để xem các mục trong document root."

    return {
        "columns": columns,
        "rows": rows,
        "forms": forms,
        "metrics": metrics,
        "notice": notice,
        "warning": warning,
        "websites": websites,
        "row_ids": row_ids,
        "row_actions": row_actions,
        "schedule_rows": schedule_rows,
        "schedule_ids": schedule_ids,
        "selected_website_id": selected_website_id if module == "files" else None,
        "current_path": current_path if module == "files" else "",
        "public_dir": public_dir if module == "files" else "",
        "file_website": file_website,
        "tree_dirs": tree_dirs,
        "disk_used": disk_used,
        "disk_total": disk_total,
        "php_versions": php_versions,
        "php_config_files": php_config_files,
        "selected_php_version": selected_php_version,
        "selected_php_file": selected_php_file,
        "php_edit": php_edit,
        "file_icons": file_icons,
    }


def _format_bytes(value):
    size = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}"
        size /= 1024


def collect_metrics():
    try:
        def cpu_times():
            fields = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
            values = [int(value) for value in fields]
            return sum(values), values[3] + (values[4] if len(values) > 4 else 0)

        cpu_before = cpu_times()
        time.sleep(0.12)
        cpu_after = cpu_times()
        elapsed_total = cpu_after[0] - cpu_before[0]
        cpu_percent = (1 - (cpu_after[1] - cpu_before[1]) / elapsed_total) * 100 if elapsed_total > 0 else None
        with open("/proc/meminfo", encoding="ascii") as stream:
            info = {line.split(":", 1)[0]: int(line.split()[1]) * 1024 for line in stream if ":" in line}
        total = info.get("MemTotal", 0)
        available = info.get("MemAvailable", info.get("MemFree", 0))
        used = max(total - available, 0)
        disk = shutil.disk_usage("/")
        load = os.getloadavg()[0]
        try:
            uptime = int(float(Path("/proc/uptime").read_text().split()[0]))
        except (OSError, ValueError):
            uptime = 0
        values = [
            {"label": "CPU", "value": f"{cpu_percent:.1f}%" if cpu_percent is not None else "Không có dữ liệu"},
            {"label": "RAM", "value": f"{_format_bytes(used)} / {_format_bytes(total)} ({used / total * 100:.1f}%)" if total else "Không có dữ liệu"},
            {"label": "Đĩa hệ thống", "value": f"{_format_bytes(disk.used)} / {_format_bytes(disk.total)} ({disk.used / disk.total * 100:.1f}%)" if disk.total else "Không có dữ liệu"},
            {"label": "Tải trung bình 1 phút", "value": f"{load:.2f}"},
            {"label": "Uptime", "value": f"{uptime // 86400} ngày, {(uptime % 86400) // 3600} giờ"},
        ]
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO system_metrics (cpu_percent, memory_percent, memory_used_bytes, memory_total_bytes, disk_percent, disk_used_bytes, disk_total_bytes, load_1m, uptime_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (cpu_percent, used / total * 100 if total else None, used, total, disk.used / disk.total * 100 if disk.total else None, disk.used, disk.total, load, uptime),
            )
            conn.execute("DELETE FROM system_metrics WHERE id NOT IN (SELECT id FROM system_metrics ORDER BY id DESC LIMIT 10080)")
        return values
    except (OSError, ValueError, ZeroDivisionError):
        return [{"label": "Máy chủ", "value": "Không lấy được dữ liệu hệ thống."}]


def render_module(request: Request, module: str, *, error=None, success=None, one_time_secret=None, edit_file=None, php_edit=None):
    title, description, _ = MODULES[module]
    phpmyadmin_installed = Path("/usr/share/phpmyadmin/index.php").is_file() if module == "databases" else False
    # Use server IP from env instead of request.url.hostname to prevent Host-header injection.
    _panel_host = os.environ.get("NEOPANEL_PUBLIC_IP", "").strip() or "127.0.0.1"
    phpmyadmin_url = f"http://{_panel_host}:8081/" if phpmyadmin_installed else None
    data = get_module_data(module, request)
    data["forms"] = [
        {**form, "enabled": has_permission(request, f"{module}.{form['action']}")}
        for form in data["forms"]
    ]
    row_permission = {
        "domains": "domains.check_dns",
        "dns": "dns.delete_record",
        "databases": "databases.delete_database",
        "files": "files.delete_file",
        "users": "users.toggle_user",
    }.get(module)
    data["row_action_enabled"] = bool(row_permission and has_permission(request, row_permission))
    data["can_manage_schedules"] = has_permission(request, "backups.manage_schedule") if module == "backups" else False
    data["can_download_backups"] = has_permission(request, "backups.read") if module == "backups" else False
    data["can_save_php_config"] = has_permission(request, "php.save_config") if module == "php" else False
    if php_edit:
        data["php_edit"] = php_edit
        data["selected_php_version"] = php_edit.get("version", "")
        data["selected_php_file"] = php_edit.get("path", "")
        try:
            data["php_config_files"] = run_operation("php_config_list", {"version": php_edit["version"]}).get("files", [])
        except OperationError:
            pass
    return templates.TemplateResponse(
        request=request,
        name="module.html",
        context={
            **data,
            "module": module,
            "title": title,
            "description": description,
            "username": request.session.get("username", ""),
            "csrf_token": get_csrf_token(request),
            "nav_groups": NAV_GROUPS,
            "nav_shell": NAV_SHELL,
            "active_module": module,
            "role_label": role_label(request.session.get("role")),
            "os_label": host_os_label(),
            "error": error,
            "success": success,
            "one_time_secret": one_time_secret,
            "edit_file": edit_file,
            "phpmyadmin_url": phpmyadmin_url,
            "phpmyadmin_installed": phpmyadmin_installed,
            "can_upload": has_permission(request, "files.upload_file"),
            "can_create_dir": has_permission(request, "files.create_directory"),
            "can_create_file": has_permission(request, "files.create_file"),
            "can_assign_php": has_permission(request, "php.assign_php"),
            "can_save_php_config": data.get("can_save_php_config"),
        },
    )


@router.get("/modules/{module}")
def module_page(module: str, request: Request):
    if module not in MODULES:
        return RedirectResponse("/", status_code=303)
    user = signed_in_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not has_permission(request, MODULES[module][2]):
        return HTMLResponse("Bạn không có quyền truy cập module này.", status_code=403)
    return render_module(request, module, success=(request.query_params.get("ok") or "")[:200] or None)


def queue_job(kind: str, resource_type: str, resource_id: int, user_id: int, payload=None) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO jobs (kind, resource_type, resource_id, requested_by, message, payload_json) VALUES (?, ?, ?, ?, ?, ?)",
            (kind, resource_type, resource_id, user_id, "Đang chờ xử lý", json.dumps(payload or {})),
        )
        return cursor.lastrowid


def run_module_job(job_id: int):
    with get_connection() as conn:
        job = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if not job:
            return
        payload = json.loads(job["payload_json"] or "{}")
        resource = None
        if job["kind"] in {"website_backup", "website_restore"}:
            backup_row = conn.execute("SELECT website_id FROM backups WHERE id = ?", (job["resource_id"],)).fetchone()
            if backup_row and backup_row["website_id"]:
                resource = conn.execute("SELECT * FROM websites WHERE id = ?", (backup_row["website_id"],)).fetchone()
        conn.execute("UPDATE jobs SET status = 'running', progress = 10, started_at = CURRENT_TIMESTAMP WHERE id = ?", (job_id,))

    try:
        if job["kind"] == "certificate_issue":
            result = run_operation("certificate_issue", payload)
            with get_connection() as conn:
                conn.execute(
                    "UPDATE ssl_certificates SET status = 'active', issuer = 'Let\'s Encrypt', issued_at = CURRENT_TIMESTAMP, expires_at = ?, last_error = NULL WHERE id = ?",
                    (result.get("expires_at"), job["resource_id"]),
                )
        elif job["kind"] == "website_backup":
            result = run_operation(
                "backup_website",
                {"domain": resource["domain"], "document_root": resource["document_root"]},
            )
            with get_connection() as conn:
                conn.execute(
                    "UPDATE backups SET status = 'completed', file_path = ?, size_bytes = ?, checksum = ? WHERE id = ?",
                    (result["file_path"], result["size_bytes"], result.get("checksum"), job["resource_id"]),
                )
        elif job["kind"] == "database_backup":
            result = run_operation("backup_database", payload)
            with get_connection() as conn:
                conn.execute(
                    "UPDATE backups SET status = 'completed', file_path = ?, size_bytes = ?, checksum = ? WHERE id = ?",
                    (result["file_path"], result["size_bytes"], result.get("checksum"), job["resource_id"]),
                )
        elif job["kind"] == "website_restore":
            result = run_operation("restore_website", payload)
            with get_connection() as conn:
                conn.execute("UPDATE backups SET status = 'completed' WHERE id = ?", (job["resource_id"],))
        elif job["kind"] == "database_restore":
            result = run_operation("restore_database", payload)
            with get_connection() as conn:
                conn.execute("UPDATE backups SET status = 'completed' WHERE id = ?", (job["resource_id"],))
        else:
            raise OperationError("Loại tác vụ không được hỗ trợ.")

        with get_connection() as conn:
            conn.execute("UPDATE jobs SET status = 'succeeded', progress = 100, message = 'Hoàn tất', finished_at = CURRENT_TIMESTAMP WHERE id = ?", (job_id,))
        record_event(None, job["kind"], user_id=job["requested_by"], resource_type=job["resource_type"], resource_id=job["resource_id"])
    except Exception as exc:
        message = str(exc)[:240] if isinstance(exc, OperationError) else "Tác vụ lỗi nội bộ."
        with get_connection() as conn:
            if job["kind"] == "certificate_issue":
                conn.execute("UPDATE ssl_certificates SET status = 'failed', last_error = ? WHERE id = ?", (message, job["resource_id"]))
            elif job["kind"] in {"website_backup", "database_backup"}:
                conn.execute("UPDATE backups SET status = 'failed', error = ? WHERE id = ?", (message, job["resource_id"]))
            conn.execute("UPDATE jobs SET status = 'failed', error = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?", (message, job_id))
        record_event(None, job["kind"], user_id=job["requested_by"], resource_type=job["resource_type"], resource_id=job["resource_id"], result="failure", details={"error": message})


def action_error(request: Request, module: str, message: str, status_code: int = 400):
    response = render_module(request, module, error=message)
    response.status_code = status_code
    return response


def action_is_rate_limited(user_id: int, action: str, limit: int = 3, window_minutes: int = 5) -> bool:
    """Prevent submitting the same heavy action more than `limit` times per window."""
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS n FROM jobs
            WHERE requested_by = ?
              AND kind = ?
              AND status IN ('queued', 'running')
            """,
            (user_id, action),
        ).fetchone()
    return row["n"] >= limit


@router.post("/modules/{module}/actions")
async def module_action(module: str, request: Request, background_tasks: BackgroundTasks):
    if module not in MODULES:
        return RedirectResponse("/", status_code=303)
    user = signed_in_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    action = str(form.get("action", ""))
    permission = f"{module}.{action}"
    if not has_permission(request, permission):
        return action_error(request, module, "Bạn không có quyền thực hiện thao tác này.", 403)
    if not valid_csrf(request, str(form.get("csrf_token", ""))):
        return action_error(request, module, "Phiên làm việc không hợp lệ. Hãy tải lại trang.", 403)

    # Rate-limit heavy / destructive actions to prevent job flooding.
    _heavy_actions = {
        "certificate_issue", "restore_backup", "create_backup",
        "create_database_backup", "create_user",
    }
    if action in _heavy_actions and action_is_rate_limited(user["id"], action):
        return action_error(
            request, module,
            "Bạn đã gửi quá nhiều yêu cầu cùng loại. Hãy chờ các tác vụ hiện tại hoàn thành.",
            429,
        )

    try:
        if module == "dns" and action == "add_record":
            domain_id = int(form.get("domain_id", "0"))
            rtype = str(form.get("type", "")).upper()
            name = str(form.get("name", "")).strip() or "@"
            value = str(form.get("value", "")).strip()
            raw_priority = str(form.get("priority", "")).strip()
            raw_ttl = str(form.get("ttl", "")).strip()
            priority = int(raw_priority) if raw_priority else (10 if rtype == "MX" else None)
            ttl = int(raw_ttl) if raw_ttl else 3600
            with get_connection() as conn:
                domain = conn.execute("SELECT id, domain, website_id FROM domains WHERE id = ?", (domain_id,)).fetchone()
            if not domain:
                raise ValueError("Hãy chọn tên miền hợp lệ.")
            if not website_in_scope(request, domain["website_id"]):
                raise ValueError("Website nằm ngoài phạm vi được cấp quyền.")
            priority = validate_dns_record(rtype, name, value, priority, ttl)
            with get_connection() as conn:
                cursor = conn.execute(
                    "INSERT INTO dns_records (domain_id, name, type, value, priority, ttl) VALUES (?, ?, ?, ?, ?, ?)",
                    (domain_id, name, rtype, value, priority, ttl),
                )
                record_id = cursor.lastrowid
            try:
                result = sync_zone(domain_id)
            except OperationError:
                with get_connection() as conn:
                    conn.execute("DELETE FROM dns_records WHERE id = ?", (record_id,))
                raise
            record_event(request, action, user_id=user["id"], username=user["username"], resource_type="dns_record", resource_id=f"{name}.{domain['domain']} {rtype}")
            message = "Đã thêm bản ghi và cập nhật BIND9." if result.get("applied") else "Đã lưu bản ghi. Chưa áp dụng vì BIND9 chưa được cài trên máy chủ."
            return render_module(request, module, success=message)

        if module == "dns" and action == "delete_record":
            record_id = int(form.get("record_id", "0"))
            with get_connection() as conn:
                record = conn.execute(
                    """SELECT r.*, d.website_id FROM dns_records r JOIN domains d ON d.id = r.domain_id WHERE r.id = ?""",
                    (record_id,),
                ).fetchone()
            if not record:
                raise ValueError("Không tìm thấy bản ghi.")
            if not website_in_scope(request, record["website_id"]):
                raise ValueError("Website nằm ngoài phạm vi được cấp quyền.")
            with get_connection() as conn:
                conn.execute("DELETE FROM dns_records WHERE id = ?", (record_id,))
            try:
                result = sync_zone(record["domain_id"])
            except OperationError:
                with get_connection() as conn:
                    conn.execute(
                        "INSERT INTO dns_records (id, domain_id, name, type, value, priority, ttl) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (record["id"], record["domain_id"], record["name"], record["type"], record["value"], record["priority"], record["ttl"]),
                    )
                raise
            record_event(request, action, user_id=user["id"], username=user["username"], resource_type="dns_record", resource_id=record_id)
            return render_module(request, module, success="Đã xóa bản ghi DNS.")

        if module == "domains" and action == "add_domain":
            domain = str(form.get("domain", "")).strip().lower().rstrip(".")
            website_id = int(form.get("website_id", "0"))
            if not domains_valid(domain):
                raise ValueError("Tên miền không hợp lệ.")
            with get_connection() as conn:
                website = conn.execute("SELECT id, domain, status FROM websites WHERE id = ?", (website_id,)).fetchone()
                if not website:
                    raise ValueError("Hãy chọn website hợp lệ.")
                if conn.execute("SELECT 1 FROM domains WHERE domain = ?", (domain,)).fetchone() or conn.execute("SELECT 1 FROM websites WHERE domain = ?", (domain,)).fetchone():
                    raise ValueError("Tên miền này đã được gắn với một website khác.")
            if not website_in_scope(request, website_id):
                raise ValueError("Website nằm ngoài phạm vi được cấp quyền.")
            if website["status"] not in {"active", "disabled"}:
                raise ValueError("Website chưa được tạo xong trên máy chủ, hãy thử lại sau.")
            # Update Nginx first; only record the domain if the server accepted it.
            run_operation("website_aliases", {"domain": website["domain"], "aliases": website_aliases(website_id) + [domain]})
            with get_connection() as conn:
                conn.execute("INSERT INTO domains (website_id, domain) VALUES (?, ?)", (website_id, domain))
            record_event(request, action, user_id=user["id"], username=user["username"], resource_type="domain", resource_id=domain)
            return render_module(request, module, success="Đã thêm domain và cập nhật Nginx.")

        if module == "domains" and action == "remove_domain":
            domain_id = int(form.get("domain_id", "0"))
            confirmation = str(form.get("confirm_domain", ""))
            with get_connection() as conn:
                domain = conn.execute("SELECT id, domain, website_id, is_primary FROM domains WHERE id = ?", (domain_id,)).fetchone()
                if not domain or domain["is_primary"] or confirmation != domain["domain"]:
                    raise ValueError("Không thể xóa domain chính hoặc tên xác nhận không khớp.")
                if not website_in_scope(request, domain["website_id"]):
                    raise ValueError("Website nằm ngoài phạm vi được cấp quyền.")
                website = conn.execute("SELECT domain, status FROM websites WHERE id = ?", (domain["website_id"],)).fetchone()
            if website and website["status"] in {"active", "disabled"}:
                remaining = [d for d in website_aliases(domain["website_id"]) if d.lower() != domain["domain"].lower()]
                run_operation("website_aliases", {"domain": website["domain"], "aliases": remaining})
            with get_connection() as conn:
                conn.execute("DELETE FROM domains WHERE id = ?", (domain_id,))
            record_event(request, action, user_id=user["id"], username=user["username"], resource_type="domain", resource_id=domain["domain"])
            return render_module(request, module, success="Đã gỡ domain khỏi website và cập nhật Nginx.")

        if module == "domains" and action == "check_dns":
            domain_id = int(form.get("domain_id", "0"))
            with get_connection() as conn:
                domain = conn.execute("SELECT id, domain, website_id FROM domains WHERE id = ?", (domain_id,)).fetchone()
            if not domain:
                raise ValueError("Không tìm thấy domain.")
            if not website_in_scope(request, domain["website_id"]):
                raise ValueError("Website nằm ngoài phạm vi được cấp quyền.")
            expected_ip = os.environ.get("NEOPANEL_PUBLIC_IP", "").strip()
            try:
                addresses = sorted({item[4][0] for item in socket.getaddrinfo(domain["domain"], None)})
            except OSError:
                addresses = []
            status = "unknown" if not expected_ip else ("valid" if expected_ip in addresses else "invalid")
            with get_connection() as conn:
                conn.execute("UPDATE domains SET dns_status = ?, checked_at = CURRENT_TIMESTAMP WHERE id = ?", (status, domain_id))
            record_event(request, action, user_id=user["id"], username=user["username"], resource_type="domain", resource_id=domain["domain"], result="warning" if status != "valid" else "success", details={"dns_status": status, "addresses": addresses})
            return render_module(request, module, success=f"DNS của {domain['domain']}: {status}.")

        if module == "php" and action == "assign_php":
            website_id = int(form.get("website_id", "0"))
            version = str(form.get("php_version", ""))
            if not website_in_scope(request, website_id):
                raise ValueError("Website nằm ngoài phạm vi được cấp quyền.")
            with get_connection() as conn:
                website = conn.execute("SELECT * FROM websites WHERE id = ?", (website_id,)).fetchone()
            if not website:
                raise ValueError("Không tìm thấy website.")
            versions = run_operation("php_versions").get("versions", [])
            if version not in versions:
                raise ValueError("Phiên bản PHP-FPM chưa được cài đặt.")
            run_operation("website_create", {"domain": website["domain"], "document_root": website["document_root"], "php_version": version, "aliases": website_aliases(website_id), "webroot": website["public_dir"]})
            with get_connection() as conn:
                conn.execute("UPDATE websites SET php_version = ?, status = 'active' WHERE id = ?", (version, website_id))
            record_event(request, action, user_id=user["id"], username=user["username"], resource_type="website", resource_id=website_id, details={"php_version": version})
            next_url = str(form.get("next", ""))
            if next_url.startswith("/modules/files"):
                return RedirectResponse(f"{next_url}{'&' if '?' in next_url else '?'}ok={quote('Đã áp dụng PHP ' + version + '.')}", status_code=303)
            return render_module(request, module, success=f"Đã áp dụng PHP {version} cho {website['domain']}.")

        if module == "php" and action == "save_config":
            version = str(form.get("version", "")).strip()
            relative = str(form.get("path", "")).strip()
            content = str(form.get("content", ""))
            try:
                result = run_operation("php_config_write", {"version": version, "path": relative, "content": content})
            except OperationError as exc:
                listed = []
                try:
                    listed = run_operation("php_config_list", {"version": version}).get("files", [])
                except OperationError:
                    pass
                label = next((item["label"] for item in listed if item["path"] == relative), relative)
                record_event(request, action, user_id=user["id"], username=user["username"], resource_type="php_config", resource_id=f"{version}:{relative}", result="failure", details={"error": str(exc)[:240]})
                return render_module(
                    request,
                    module,
                    error=str(exc),
                    php_edit={"version": version, "path": relative, "label": label, "content": content, "exists": True},
                )
            record_event(request, action, user_id=user["id"], username=user["username"], resource_type="php_config", resource_id=f"{version}:{relative}")
            message = f"Đã lưu {relative} cho PHP {version}."
            if result.get("reloaded"):
                message += " PHP-FPM đã được nạp lại."
            return RedirectResponse(
                f"/modules/php?version={quote(version)}&file={quote(relative)}&ok={quote(message)}",
                status_code=303,
            )

        if module == "files" and action in FILE_ACTIONS:
            website_id = int(form.get("website_id", "0"))
            with get_connection() as conn:
                website = conn.execute("SELECT id, domain, document_root, public_dir FROM websites WHERE id = ?", (website_id,)).fetchone()
            if not website:
                raise ValueError("Không tìm thấy website.")
            if not website_in_scope(request, website_id):
                raise ValueError("Website nằm ngoài phạm vi được cấp quyền.")
            root = Path(website["document_root"]).resolve()
            domain = website["domain"]

            def clean_rel(value, label="Đường dẫn", allow_empty=False):
                value = str(value or "").strip().strip("/")
                candidate = Path(value)
                if candidate.is_absolute() or ".." in candidate.parts or (not value and not allow_empty):
                    raise ValueError(f"{label} không hợp lệ.")
                if not (root / candidate).resolve().is_relative_to(root):
                    raise ValueError(f"{label} vượt khỏi document root.")
                return candidate

            def clean_name(value, label="Tên"):
                value = str(value or "").strip()
                if value in {"", ".", ".."} or Path(value).name != value or len(value) > 180:
                    raise ValueError(f"{label} không hợp lệ.")
                return value

            directory = str(clean_rel(form.get("directory", ""), "Đường dẫn thư mục", allow_empty=True))
            directory = "" if directory == "." else directory
            redirect_path = directory
            message = "Hoàn tất."

            # Mapping of known dangerous magic-byte signatures to block server-side execution.
            _BLOCKED_MAGIC = {
                b"\x7fELF": "ELF binary",
                b"MZ": "PE/Windows executable",
                b"#!/": "shell script (shebang)",
                b"#! /": "shell script (shebang)",
            }

            if action == "upload_file":
                uploads = [item for item in form.getlist("file") if hasattr(item, "read") and item.filename]
                if not uploads:
                    raise ValueError("Hãy chọn tệp cần tải lên.")
                if len(uploads) > 20:
                    raise ValueError("Mỗi lần chỉ tải tối đa 20 tệp.")
                for upload in uploads:
                    filename = clean_name(Path(upload.filename).name, "Tên tệp")
                    file_bytes = await upload.read(MAX_UPLOAD_BYTES + 1)
                    if len(file_bytes) > MAX_UPLOAD_BYTES:
                        raise ValueError(f"{filename}: kích thước tối đa mỗi tệp là 100 MB.")
                    # Detect and log actual file type from magic bytes.
                    magic_head = file_bytes[:8]
                    for sig, label in _BLOCKED_MAGIC.items():
                        if magic_head.startswith(sig):
                            record_event(
                                request, "upload_blocked",
                                user_id=user["id"], username=user["username"],
                                resource_type="file",
                                resource_id=f"{domain}/{directory}/{filename}",
                                result="warning",
                                details={"reason": f"blocked magic bytes: {label}"},
                            )
                            raise ValueError(f"{filename}: loại tệp không được phép tải lên ({label}).")
                    relative = Path(directory) / filename
                    clean_rel(str(relative), "Đường dẫn tải lên")
                    run_operation("file_write", {"domain": domain, "path": str(relative), "content": base64.b64encode(file_bytes).decode("ascii")})
                resource = f"{len(uploads)} tệp"
                message = f"Đã tải lên {len(uploads)} tệp."
            elif action == "create_directory":
                name = clean_name(form.get("name"), "Tên thư mục")
                relative = Path(directory) / name
                clean_rel(str(relative), "Đường dẫn thư mục")
                run_operation("file_mkdir", {"domain": domain, "path": str(relative)})
                resource = str(relative)
                message = f"Đã tạo thư mục {name}."
            elif action == "create_file":
                name = clean_name(form.get("name"), "Tên tệp")
                relative = Path(directory) / name
                clean_rel(str(relative), "Đường dẫn tệp")
                if (root / relative).exists():
                    raise ValueError("Đã có tệp hoặc thư mục cùng tên.")
                run_operation("file_write", {"domain": domain, "path": str(relative), "content": ""})
                resource = str(relative)
                message = f"Đã tạo tệp {name}."
            elif action == "save_file":
                relative = clean_rel(form.get("path"), "Đường dẫn tệp")
                text = str(form.get("content", "")).replace("\r\n", "\n")
                data_bytes = text.encode("utf-8")
                if len(data_bytes) > 2 * 1024 * 1024:
                    raise ValueError("Nội dung vượt quá 2 MB.")
                run_operation("file_write", {"domain": domain, "path": str(relative), "content": base64.b64encode(data_bytes).decode("ascii")})
                record_event(request, action, user_id=user["id"], username=user["username"], resource_type="file", resource_id=f"{domain}/{relative}")
                return RedirectResponse(f"/modules/files/edit?website_id={website_id}&path={quote(str(relative))}&saved=1", status_code=303)
            elif action == "delete_file":
                relative = str(clean_rel(form.get("path"), "Đường dẫn"))
                if str(form.get("confirm_path", "")).strip() != relative:
                    raise ValueError("Đường dẫn xác nhận không khớp; mục chưa bị xóa.")
                is_dir = (root / relative).is_dir() and not (root / relative).is_symlink()
                run_operation("file_delete", {"domain": domain, "path": relative, "recursive": is_dir})
                resource = relative
                message = "Đã xóa mục đã xác nhận."
            elif action == "rename_file":
                relative = str(clean_rel(form.get("path"), "Đường dẫn"))
                new_name = clean_name(form.get("new_name"), "Tên mới")
                target = str(Path(relative).parent / new_name)
                run_operation("file_rename", {"domain": domain, "source": relative, "target": target})
                resource = relative
                message = "Đã đổi tên mục."
            elif action == "move_file":
                relative = str(clean_rel(form.get("path"), "Đường dẫn"))
                dest_dir = clean_rel(form.get("dest_dir", ""), "Thư mục đích", allow_empty=True)
                if not (root / dest_dir).is_dir():
                    raise ValueError("Thư mục đích không tồn tại.")
                target = str(dest_dir / Path(relative).name)
                run_operation("file_rename", {"domain": domain, "source": relative, "target": target})
                resource = relative
                message = f"Đã di chuyển tới /{dest_dir if str(dest_dir) != '.' else ''}."
            elif action == "copy_file":
                relative = str(clean_rel(form.get("path"), "Đường dẫn"))
                source = Path(relative)
                dest_raw = str(form.get("dest_dir", "")).strip()
                dest_dir = clean_rel(dest_raw, "Thư mục đích", allow_empty=True) if dest_raw else source.parent
                if not (root / dest_dir).is_dir():
                    raise ValueError("Thư mục đích không tồn tại.")
                name = source.name
                if dest_dir == source.parent:
                    name = f"{source.stem}-copy{source.suffix}" if (root / source).is_file() else f"{source.name}-copy"
                run_operation("file_copy", {"domain": domain, "source": relative, "target": str(dest_dir / name)})
                resource = relative
                message = f"Đã sao chép thành {name}."
            elif action == "archive_file":
                relative = str(clean_rel(form.get("path"), "Đường dẫn"))
                run_operation("file_archive", {"domain": domain, "sources": [relative], "target": f"{relative}.zip"})
                resource = relative
                message = f"Đã nén thành {Path(relative).name}.zip."
            elif action == "extract_file":
                relative = str(clean_rel(form.get("path"), "Đường dẫn"))
                extract_raw = str(form.get("extract_dir", "")).strip()
                target_dir = str(clean_rel(extract_raw, "Thư mục giải nén", allow_empty=True)) if extract_raw else directory
                target_dir = "" if target_dir == "." else target_dir
                result = run_operation("file_extract", {"domain": domain, "path": relative, "target_dir": target_dir})
                resource = relative
                message = f"Đã giải nén {result.get('extracted', 0)} mục."
                if result.get("laravel"):
                    if result.get("base") == "" and website["public_dir"] != "public":
                        run_operation("website_webroot", {"domain": domain, "subdir": "public"})
                        with get_connection() as conn:
                            conn.execute("UPDATE websites SET public_dir = 'public' WHERE id = ?", (website_id,))
                        message += " Phát hiện Laravel: đã đặt thư mục web gốc là public/. Hãy tạo file .env và database."
                    elif result.get("base"):
                        message += f" Phát hiện Laravel trong /{result['base']}. Hãy đặt thư mục web gốc là {result['base']}/public."
            elif action in {"bulk_archive", "bulk_delete", "bulk_move", "bulk_copy"}:
                selected = [str(clean_rel(item, "Đường dẫn")) for item in form.getlist("paths")]
                if not selected:
                    raise ValueError("Hãy chọn ít nhất một mục (tick ô bên trái).")
                if len(selected) > 200:
                    raise ValueError("Mỗi lần chỉ thao tác tối đa 200 mục.")
                resource = f"{len(selected)} mục"
                if action == "bulk_archive":
                    zip_name = clean_name(form.get("zip_name") or "archive.zip", "Tên tệp zip")
                    if not zip_name.lower().endswith(".zip"):
                        zip_name += ".zip"
                    run_operation("file_archive", {"domain": domain, "sources": selected, "target": str(Path(directory) / zip_name)})
                    message = f"Đã nén {len(selected)} mục thành {zip_name}."
                elif action == "bulk_delete":
                    for item in selected:
                        is_dir = (root / item).is_dir() and not (root / item).is_symlink()
                        run_operation("file_delete", {"domain": domain, "path": item, "recursive": is_dir})
                    message = f"Đã xóa {len(selected)} mục."
                else:
                    dest_raw = str(form.get("dest_dir", "")).strip()
                    if action == "bulk_move" or dest_raw:
                        dest_dir = clean_rel(dest_raw, "Thư mục đích", allow_empty=True)
                    else:
                        dest_dir = Path(directory)
                    if not (root / dest_dir).is_dir():
                        raise ValueError("Thư mục đích không tồn tại.")
                    for item in selected:
                        source = Path(item)
                        target = dest_dir / source.name
                        if action == "bulk_move":
                            run_operation("file_rename", {"domain": domain, "source": item, "target": str(target)})
                        else:
                            if dest_dir == source.parent:
                                target = dest_dir / (f"{source.stem}-copy{source.suffix}" if (root / source).is_file() else f"{source.name}-copy")
                            run_operation("file_copy", {"domain": domain, "source": item, "target": str(target)})
                    message = f"Đã {'di chuyển' if action == 'bulk_move' else 'sao chép'} {len(selected)} mục."
            else:  # set_webroot
                subdir = str(form.get("subdir", "")).strip().strip("/")
                if subdir and (".." in subdir.split("/") or not re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+){0,3}", subdir)):
                    raise ValueError("Thư mục web gốc không hợp lệ.")
                run_operation("website_webroot", {"domain": domain, "subdir": subdir})
                with get_connection() as conn:
                    conn.execute("UPDATE websites SET public_dir = ? WHERE id = ?", (subdir, website_id))
                resource = subdir or "/"
                message = f"Đã đặt thư mục web gốc: /{subdir}."
            record_event(request, action, user_id=user["id"], username=user["username"], resource_type="file", resource_id=f"{domain}/{resource}")
            return RedirectResponse(f"/modules/files?website_id={website_id}&path={quote(redirect_path)}&ok={quote(message)}", status_code=303)

        if module == "databases" and action == "create_database":
            requested = str(form.get("name", "")).strip().lower()
            website_id = int(form.get("website_id", "0"))
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,35}", requested):
                raise ValueError("Tên phải bắt đầu bằng chữ thường và chỉ dùng chữ thường, số, dấu gạch dưới.")
            with get_connection() as conn:
                website = conn.execute("SELECT id, domain FROM websites WHERE id = ?", (website_id,)).fetchone()
                duplicate = conn.execute("SELECT 1 FROM hosting_databases WHERE name = ? OR username = ?", (requested, requested)).fetchone()
            if not website or duplicate:
                raise ValueError("Website không hợp lệ hoặc tên database đã được sử dụng.")
            if not website_in_scope(request, website_id):
                raise ValueError("Website nằm ngoài phạm vi được cấp quyền.")
            custom_password = str(form.get("password", ""))
            if custom_password:
                if not 8 <= len(custom_password) <= 128 or any(not 32 <= ord(c) < 127 for c in custom_password):
                    raise ValueError("Mật khẩu phải dài 8–128 ký tự, chỉ gồm ký tự ASCII hiển thị được (không dấu tiếng Việt, không xuống dòng).")
                password = custom_password
                generated = False
            else:
                password = secrets.token_urlsafe(32)
                generated = True
            run_operation("database_create", {"name": requested, "username": requested, "password": password})
            with get_connection() as conn:
                conn.execute("INSERT INTO hosting_databases (website_id, name, username, status) VALUES (?, ?, ?, 'active')", (website_id, requested, requested))
            record_event(request, action, user_id=user["id"], username=user["username"], resource_type="database", resource_id=requested)
            if generated:
                response = render_module(request, module, success="Database đã được tạo. Hãy lưu mật khẩu ngay.", one_time_secret={"username": requested, "password": password})
            else:
                response = render_module(request, module, success=f"Database đã được tạo với mật khẩu bạn nhập. Tài khoản: {requested}.")
            response.headers["Cache-Control"] = "no-store"
            return response
            
        if module == "databases" and action == "delete_database":
            database_id = int(form.get("database_id", "0"))
            confirm = str(form.get("confirm_name", ""))
            with get_connection() as conn:
                database = conn.execute("SELECT * FROM hosting_databases WHERE id = ? AND status = 'active'", (database_id,)).fetchone()
            if not database or confirm != database["name"]:
                raise ValueError("Tên xác nhận không khớp; database chưa bị xóa.")
            run_operation("database_delete", {"name": database["name"], "username": database["username"]})
            with get_connection() as conn:
                conn.execute("UPDATE hosting_databases SET status = 'deleted' WHERE id = ?", (database_id,))
            record_event(request, action, user_id=user["id"], username=user["username"], resource_type="database", resource_id=database["name"])
            return render_module(request, module, success="Đã xóa database sau khi xác nhận.")

        if module == "ssl" and action == "issue_certificate":
            website_id = int(form.get("website_id", "0"))
            email = str(form.get("email", "")).strip()
            with get_connection() as conn:
                website = conn.execute("SELECT id, domain FROM websites WHERE id = ?", (website_id,)).fetchone()
                primary = conn.execute("SELECT domain FROM domains WHERE website_id = ? AND is_primary = 1", (website_id,)).fetchone()
                if not primary and website:
                    primary = {"domain": website["domain"]}
                if not website or not primary:
                    raise ValueError("Không tìm thấy website hoặc domain chính.")
                if not website_in_scope(request, website_id):
                    raise ValueError("Website nằm ngoài phạm vi được cấp quyền.")
                cursor = conn.execute("INSERT INTO ssl_certificates (website_id, domain, status) VALUES (?, ?, 'pending')", (website_id, primary["domain"]))
                certificate_id = cursor.lastrowid
            job_id = queue_job("certificate_issue", "certificate", certificate_id, user["id"], {"domain": primary["domain"], "email": email})
            background_tasks.add_task(run_module_job, job_id)
            record_event(request, action + "_requested", user_id=user["id"], username=user["username"], resource_type="certificate", resource_id=primary["domain"])
            return render_module(request, module, success="Đã xếp yêu cầu cấp SSL vào hàng đợi. Theo dõi trạng thái tại bảng chứng chỉ.")

        if module == "backups" and action == "create_backup":
            website_id = int(form.get("website_id", "0"))
            with get_connection() as conn:
                website = conn.execute("SELECT id FROM websites WHERE id = ? AND status = 'active'", (website_id,)).fetchone()
                if not website:
                    raise ValueError("Chỉ có thể sao lưu website đang hoạt động.")
                if not website_in_scope(request, website_id):
                    raise ValueError("Website nằm ngoài phạm vi được cấp quyền.")
                cursor = conn.execute("INSERT INTO backups (website_id, kind, file_path, status) VALUES (?, 'website', '', 'queued')", (website_id,))
                backup_id = cursor.lastrowid
            job_id = queue_job("website_backup", "backup", backup_id, user["id"])
            background_tasks.add_task(run_module_job, job_id)
            record_event(request, action + "_requested", user_id=user["id"], username=user["username"], resource_type="backup", resource_id=backup_id)
            return render_module(request, module, success="Đã xếp tác vụ sao lưu vào hàng đợi.")

        if module == "backups" and action == "create_database_backup":
            database_id = int(form.get("database_id", "0"))
            with get_connection() as conn:
                database = conn.execute("SELECT id, name, website_id FROM hosting_databases WHERE id = ? AND status = 'active'", (database_id,)).fetchone()
                if not database:
                    raise ValueError("Không tìm thấy database đang hoạt động.")
                if database["website_id"] and not website_in_scope(request, database["website_id"]):
                    raise ValueError("Database nằm ngoài phạm vi được cấp quyền.")
                cursor = conn.execute("INSERT INTO backups (website_id, database_id, kind, file_path, status) VALUES (?, ?, 'database', '', 'queued')", (database["website_id"], database_id))
                backup_id = cursor.lastrowid
            job_id = queue_job("database_backup", "backup", backup_id, user["id"], {"name": database["name"]})
            background_tasks.add_task(run_module_job, job_id)
            record_event(request, action + "_requested", user_id=user["id"], username=user["username"], resource_type="backup", resource_id=backup_id)
            return render_module(request, module, success="Đã xếp tác vụ sao lưu database vào hàng đợi.")

        if module == "backups" and action == "create_schedule":
            website_id = int(form.get("website_id", "0"))
            frequency = str(form.get("frequency", ""))
            retention_days = int(form.get("retention_days", "30"))
            if frequency not in {"daily", "weekly", "monthly"} or not 1 <= retention_days <= 3650:
                raise ValueError("Tần suất hoặc thời hạn lưu giữ không hợp lệ.")
            if not website_in_scope(request, website_id):
                raise ValueError("Website nằm ngoài phạm vi được cấp quyền.")
            with get_connection() as conn:
                exists = conn.execute("SELECT 1 FROM websites WHERE id = ?", (website_id,)).fetchone()
                if not exists:
                    raise ValueError("Không tìm thấy website.")
                conn.execute("INSERT INTO backup_schedules (website_id, kind, frequency, retention_days, next_run_at) VALUES (?, 'website', ?, ?, CURRENT_TIMESTAMP)", (website_id, frequency, retention_days))
            record_event(request, action, user_id=user["id"], username=user["username"], resource_type="backup_schedule", resource_id=website_id)
            return render_module(request, module, success="Đã lập lịch. Tác vụ chạy khi cài và kích hoạt neopanel-scheduler.timer theo hướng dẫn Ubuntu.")

        if module == "backups" and action == "toggle_schedule":
            schedule_id = int(form.get("schedule_id", "0"))
            with get_connection() as conn:
                schedule = conn.execute("SELECT id, website_id, enabled FROM backup_schedules WHERE id = ?", (schedule_id,)).fetchone()
                if not schedule:
                    raise ValueError("Không tìm thấy lịch sao lưu.")
                if not website_in_scope(request, schedule["website_id"]):
                    raise ValueError("Website nằm ngoài phạm vi được cấp quyền.")
                enabled = 0 if schedule["enabled"] else 1
                conn.execute("UPDATE backup_schedules SET enabled = ?, next_run_at = CASE WHEN ? = 1 THEN CURRENT_TIMESTAMP ELSE next_run_at END WHERE id = ?", (enabled, enabled, schedule_id))
            record_event(request, "backup_schedule_enabled" if enabled else "backup_schedule_paused", user_id=user["id"], username=user["username"], resource_type="backup_schedule", resource_id=schedule_id)
            return render_module(request, module, success="Đã cập nhật lịch sao lưu.")

        if module == "backups" and action == "restore_backup":
            backup_id = int(form.get("backup_id", "0"))
            confirmation = str(form.get("confirm_name", ""))
            with get_connection() as conn:
                backup = conn.execute("""SELECT b.*, w.domain, d.name AS database_name
                    FROM backups b LEFT JOIN websites w ON w.id = b.website_id
                    LEFT JOIN hosting_databases d ON d.id = b.database_id
                    WHERE b.id = ? AND b.status = 'completed'""", (backup_id,)).fetchone()
            if not backup:
                raise ValueError("Bản sao lưu không tồn tại hoặc chưa hoàn tất.")
            target_name = backup["domain"] or backup["database_name"]
            if confirmation != target_name:
                raise ValueError("Tên xác nhận không khớp; chưa thực hiện phục hồi.")
            if backup["website_id"] and not website_in_scope(request, backup["website_id"]):
                raise ValueError("Website nằm ngoài phạm vi được cấp quyền.")
            if backup["kind"] == "database":
                job_kind = "database_restore"
                payload = {"name": backup["database_name"], "filename": Path(backup["file_path"]).name, "checksum": backup["checksum"]}
            else:
                job_kind = "website_restore"
                payload = {"domain": backup["domain"], "file_path": backup["file_path"], "filename": Path(backup["file_path"]).name, "checksum": backup["checksum"]}
            job_id = queue_job(job_kind, "backup", backup_id, user["id"], payload)
            background_tasks.add_task(run_module_job, job_id)
            record_event(request, action + "_requested", user_id=user["id"], username=user["username"], resource_type="backup", resource_id=backup_id, result="warning")
            return render_module(request, module, success="Đã xác nhận. Tác vụ phục hồi đang chạy; có thể ghi đè dữ liệu hiện tại.")

        if module == "users" and action == "create_user":
            username = str(form.get("username", "")).strip()
            password = str(form.get("password", ""))
            role = str(form.get("role", ""))
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,50}", username) or not password:
                raise ValueError("Tên người dùng không hợp lệ hoặc mật khẩu đang để trống.")
            if role not in {"super_admin", "hosting_admin", "website_manager", "read_only"}:
                raise ValueError("Vai trò không hợp lệ.")
            assigned_ids = []
            for value in form.getlist("website_ids"):
                try:
                    assigned_ids.append(int(value))
                except ValueError:
                    raise ValueError("Danh sách website không hợp lệ.")
            if role == "website_manager" and not assigned_ids:
                raise ValueError("Website Manager cần được gán ít nhất một website.")
            with get_connection() as conn:
                cursor = conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (username, password_hasher.hash(password), role))
                new_user_id = cursor.lastrowid
                for website_id in set(assigned_ids):
                    exists = conn.execute("SELECT 1 FROM websites WHERE id = ?", (website_id,)).fetchone()
                    if not exists:
                        raise ValueError("Danh sách có website không tồn tại.")
                    conn.execute("INSERT INTO user_websites (user_id, website_id, granted_by) VALUES (?, ?, ?)", (new_user_id, website_id, user["id"]))
            record_event(request, action, user_id=user["id"], username=user["username"], resource_type="user", resource_id=username)
            return render_module(request, module, success=f"Đã tạo tài khoản {username}.")

        if module == "users" and action == "toggle_user":
            target_id = int(form.get("user_id", "0"))
            with get_connection() as conn:
                target = conn.execute("SELECT id, username, role, is_active FROM users WHERE id = ?", (target_id,)).fetchone()
                if not target or target["username"] != str(form.get("confirm_username", "")):
                    raise ValueError("Tài khoản xác nhận không khớp.")
                if target_id == user["id"] and target["is_active"]:
                    raise ValueError("Không thể khóa tài khoản đang đăng nhập.")
                if target["role"] in {"admin", "super_admin"} and target["is_active"]:
                    count = conn.execute("SELECT COUNT(*) AS n FROM users WHERE is_active = 1 AND role IN ('admin', 'super_admin')").fetchone()["n"]
                    if count <= 1:
                        raise ValueError("Không thể khóa tài khoản super admin cuối cùng.")
                new_state = 0 if target["is_active"] else 1
                conn.execute("UPDATE users SET is_active = ?, session_version = session_version + 1 WHERE id = ?", (new_state, target_id))
            record_event(request, "user_disabled" if not new_state else "user_enabled", user_id=user["id"], username=user["username"], resource_type="user", resource_id=target["username"])
            return render_module(request, module, success="Đã cập nhật trạng thái tài khoản.")

        if module == "settings" and action == "save_settings":
            timezone_name = str(form.get("timezone", "Asia/Bangkok")).strip()
            try:
                from zoneinfo import ZoneInfo
                ZoneInfo(timezone_name)
                warning = int(form.get("disk_warning_percent", "80"))
                critical = int(form.get("disk_critical_percent", "90"))
            except (ValueError, KeyError):
                raise ValueError("Múi giờ hoặc ngưỡng cảnh báo không hợp lệ.")
            if not 1 <= warning < critical <= 100:
                raise ValueError("Ngưỡng cảnh báo phải tăng dần và nằm trong khoảng 1–100%.")
            values = {"timezone": timezone_name, "disk_warning_percent": str(warning), "disk_critical_percent": str(critical)}
            with get_connection() as conn:
                for key, value in values.items():
                    conn.execute("INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = CURRENT_TIMESTAMP", (key, value, user["id"]))
            record_event(request, action, user_id=user["id"], username=user["username"], resource_type="settings")
            return render_module(request, module, success="Đã lưu cài đặt.")

        raise ValueError("Thao tác không hợp lệ cho module này.")
    except (ValueError, OperationError, OSError) as exc:
        record_event(request, action, user_id=user["id"], username=user["username"], resource_type=module, result="failure", details={"error": str(exc)[:240]})
        return action_error(request, module, str(exc))
    except sqlite3.IntegrityError:
        record_event(request, action, user_id=user["id"], username=user["username"], resource_type=module, result="failure", details={"error": "duplicate_or_referenced_record"})
        return action_error(request, module, "Bản ghi đã tồn tại hoặc đang được tham chiếu; không thể hoàn tất thao tác.")


@router.get("/modules/files/edit")
def edit_file_page(request: Request, website_id: int, path: str):
    user = signed_in_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not has_permission(request, "files.save_file"):
        return RedirectResponse("/modules/files", status_code=303)
    with get_connection() as conn:
        website = conn.execute("SELECT domain FROM websites WHERE id = ?", (website_id,)).fetchone()
    if not website or not website_in_scope(request, website_id):
        return RedirectResponse("/modules/files", status_code=303)
    candidate = Path(path)
    if candidate.is_absolute() or ".." in candidate.parts or not path:
        return RedirectResponse("/modules/files", status_code=303)
    try:
        content = base64.b64decode(run_operation("file_read", {"domain": website["domain"], "path": path})["content"])
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return action_error(request, "files", "Đây là tệp nhị phân, không thể sửa dạng văn bản.")
    except OperationError as exc:
        return action_error(request, "files", str(exc))
    parent = "" if str(candidate.parent) == "." else str(candidate.parent)
    return render_module(request, "files", success="Đã lưu tệp." if request.query_params.get("saved") else None,
                         edit_file={"path": path, "content": text, "directory": parent})


@router.get("/modules/files/download")
def download_file(request: Request, website_id: int, path: str):
    user = signed_in_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not has_permission(request, "files.read"):
        return RedirectResponse("/modules/files", status_code=303)
    with get_connection() as conn:
        website = conn.execute("SELECT domain, document_root FROM websites WHERE id = ?", (website_id,)).fetchone()
    if not website:
        return RedirectResponse("/modules/files", status_code=303)
    if not website_in_scope(request, website_id):
        return HTMLResponse("Không tìm thấy tệp.", status_code=404)
    root = Path(website["document_root"]).resolve()
    target = (root / path).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        return RedirectResponse("/modules/files", status_code=303)
    record_event(request, "file_download", user_id=user["id"], username=user["username"], resource_type="file", resource_id=f"{website['domain']}/{path}")
    return FileResponse(target, filename=target.name)


@router.get("/modules/backups/download")
def download_backup(request: Request, backup_id: int):
    user = signed_in_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not has_permission(request, "backups.read"):
        return HTMLResponse("Bạn không có quyền tải bản sao lưu.", status_code=403)
    with get_connection() as conn:
        backup = conn.execute("SELECT * FROM backups WHERE id = ? AND status = 'completed'", (backup_id,)).fetchone()
    if not backup or (backup["website_id"] and not website_in_scope(request, backup["website_id"])):
        return HTMLResponse("Không tìm thấy bản sao lưu.", status_code=404)
    target = Path(backup["file_path"]).resolve()
    backup_root = Path("/var/backups/neopanel").resolve()
    # Extra guard: filename must not contain path separators (DB tampering defence).
    if "/" in target.name or "\\" in target.name:
        return HTMLResponse("Tên tệp sao lưu không hợp lệ.", status_code=400)
    if target.parent != backup_root or not target.is_file():
        return HTMLResponse("Tệp sao lưu không khả dụng.", status_code=404)
    record_event(request, "backup_download", user_id=user["id"], username=user["username"], resource_type="backup", resource_id=backup_id)
    response = FileResponse(target, filename=target.name)
    response.headers["Cache-Control"] = "no-store"
    return response

