#!/usr/bin/env python3
"""Root-owned, narrow allowlist helper for NeoPanel on Ubuntu."""

import json
import hashlib
import gzip
import grp
import os
import pwd
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
import ipaddress
import time

BIND_DIR = Path("/etc/bind/neopanel")
DNS_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"}
DNS_NAME_RE = re.compile(r"(@|\*|[A-Za-z0-9_*][A-Za-z0-9_.-]{0,252})\Z")

WEB_ROOT = Path("/var/www/neopanel")
NGINX_AVAILABLE_DIR = Path("/etc/nginx/sites-available/neopanel")
NGINX_ENABLED_DIR = Path("/etc/nginx/sites-enabled")
BACKUP_ROOT = Path("/var/backups/neopanel")
DOMAIN_RE = re.compile(r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\Z")
IDENTIFIER_RE = re.compile(r"[a-z][a-z0-9_]{0,47}\Z")
PHP_RE = re.compile(r"[0-9]{1,2}\.[0-9]{1,2}\Z")


class OperationError(Exception):
    pass


def run(args, *, input_text=None, timeout=60):
    result = subprocess.run(
        args,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        raise OperationError("Lệnh hệ thống thất bại: " + Path(args[0]).name)
    return result.stdout.strip()


def require_domain(value):
    if not isinstance(value, str) or not DOMAIN_RE.fullmatch(value):
        raise OperationError("Tên miền không hợp lệ.")
    return value.lower()


def require_webroot(value):
    """Optional sub-directory of the document root served by Nginx (e.g. 'public')."""
    if value in (None, ""):
        return ""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+){0,3}", value):
        raise OperationError("Thư mục web gốc không hợp lệ.")
    return value


def require_aliases(primary, value):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 50:
        raise OperationError("Danh sách domain bí danh không hợp lệ.")
    aliases = []
    for item in value:
        alias = require_domain(item)
        if alias != primary and alias not in aliases:
            aliases.append(alias)
    return aliases


def require_document_root(domain, value):
    expected = WEB_ROOT / domain
    if value != str(expected):
        raise OperationError("Document root không nằm trong phạm vi cho phép.")
    return expected


def site_owner(domain):
    account = pwd.getpwnam(site_user(domain))
    return account.pw_uid, grp.getgrnam("www-data").gr_gid


def site_user(domain):
    return "np" + hashlib.sha256(domain.encode("ascii")).hexdigest()[:12]


def validate_php(version, domain):
    if not isinstance(version, str) or not PHP_RE.fullmatch(version):
        raise OperationError("Phiên bản PHP không hợp lệ.")
    fpm_config = Path(f"/etc/php/{version}/fpm/php-fpm.conf")
    executable = shutil.which(f"php-fpm{version}")
    if not fpm_config.is_file() or not executable:
        raise OperationError(f"PHP-FPM {version} chưa được cài đặt.")
    socket_path = Path(f"/run/php/neopanel-{hashlib.sha256(domain.encode('ascii')).hexdigest()[:12]}.sock")
    unit = f"php{version}-fpm"
    return socket_path, unit, executable, fpm_config


def managed_pool_path(version, domain):
    return Path(f"/etc/php/{version}/fpm/pool.d/neopanel-{hashlib.sha256(domain.encode('ascii')).hexdigest()[:12]}.conf")


def pool_config(domain, root, user, group, socket_path, session_dir):
    pool_name = site_user(domain)
    return (
        f"; managed-by-neopanel\n"
        f"[{pool_name}]\n"
        f"user = {user}\n"
        f"group = {group}\n"
        f"listen = {socket_path}\n"
        f"listen.owner = www-data\n"
        f"listen.group = www-data\n"
        f"listen.mode = 0660\n"
        f"pm = ondemand\n"
        f"pm.max_children = 8\n"
        f"pm.process_idle_timeout = 10s\n"
        f"pm.max_requests = 500\n"
        f"clear_env = yes\n"
        f"chdir = {root}\n"
        f"security.limit_extensions = .php\n"
        f"php_admin_value[open_basedir] = {root}/:/tmp/:/usr/share/php/:{session_dir}/\n"
        f"php_admin_value[session.save_path] = {session_dir}\n"
        f"php_admin_value[upload_max_filesize] = 64M\n"
        f"php_admin_value[post_max_size] = 64M\n"
    )


def reload_php(unit):
    state = subprocess.run(["/usr/bin/systemctl", "is-active", unit], capture_output=True, text=True, check=False)
    if state.stdout.strip() == "active":
        run(["/usr/bin/systemctl", "reload", unit])
    else:
        run(["/usr/bin/systemctl", "enable", "--now", unit])


def validate_nginx():
    run(["/usr/sbin/nginx", "-t"])
    run(["/usr/bin/systemctl", "reload", "nginx"])


def website_create(data):
    domain = require_domain(data.get("domain"))
    root = require_document_root(domain, data.get("document_root"))
    version = data.get("php_version")
    socket_path, php_unit, php_executable, _ = validate_php(version, domain)
    server_names = " ".join([domain, *require_aliases(domain, data.get("aliases"))])
    webroot_sub = require_webroot(data.get("webroot"))
    root.mkdir(mode=0o750, parents=True, exist_ok=True)
    username = site_user(domain)
    try:
        account = pwd.getpwnam(username)
    except KeyError:
        run(["/usr/sbin/useradd", "--system", "--user-group", "--home-dir", str(root), "--no-create-home", "--shell", "/usr/sbin/nologin", username])
        account = pwd.getpwnam(username)
    web_group = grp.getgrnam("www-data").gr_gid
    os.chown(root, account.pw_uid, web_group)
    os.chmod(root, 0o750)
    pool_name = hashlib.sha256(domain.encode("ascii")).hexdigest()[:12]
    session_dir = Path("/var/lib/php/neopanel") / pool_name
    session_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(session_dir, account.pw_uid, account.pw_gid)
    os.chmod(session_dir, 0o700)

    pool_dir = managed_pool_path(version, domain).parent
    pool_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    pool_file = managed_pool_path(version, domain)
    old_pool_files = [path for path in Path("/etc/php").glob(f"*/fpm/pool.d/{pool_file.name}") if path != pool_file]
    old_pool_text = {path: path.read_text(encoding="utf-8") for path in old_pool_files}
    previous_pool = pool_file.read_text(encoding="utf-8") if pool_file.exists() else None
    if previous_pool and "managed-by-neopanel" not in previous_pool:
        raise OperationError("Đã có PHP-FPM pool cùng tên không thuộc NeoPanel.")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=pool_dir, delete=False) as temporary:
        temporary.write(pool_config(domain, root, username, "www-data", socket_path, session_dir))
        temporary_pool = Path(temporary.name)
    temporary_pool.chmod(0o644)
    temporary_pool.replace(pool_file)
    # Validate the new pool before making Nginx point to its socket.
    try:
        run([php_executable, "-t"])
        reload_php(php_unit)
    except Exception:
        if previous_pool is None:
            pool_file.unlink(missing_ok=True)
        else:
            pool_file.write_text(previous_pool, encoding="utf-8")
        try:
            reload_php(php_unit)
        except Exception:
            pass
        raise

    NGINX_AVAILABLE_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    available = NGINX_AVAILABLE_DIR / f"{domain}.conf"
    enabled = NGINX_ENABLED_DIR / f"neopanel-{domain}.conf"
    if available.exists() and "managed-by-neopanel" not in available.read_text(encoding="utf-8"):
        raise OperationError("Đã có cấu hình Nginx cùng tên không thuộc NeoPanel.")
    if enabled.exists() or enabled.is_symlink():
        if not enabled.is_symlink() or enabled.resolve(strict=True) != available.resolve(strict=True):
            raise OperationError("Đã có một mục Nginx cùng tên không thuộc NeoPanel.")
    previous_config = available.read_text(encoding="utf-8") if available.exists() else None
    config = (
            "# managed-by-neopanel\n"
            "server {\n"
            "    listen 80;\n"
            "    listen [::]:80;\n"
            f"    server_name {server_names};\n"
            "    client_max_body_size 128m;\n"
            f"    root {root / webroot_sub if webroot_sub else root};\n"
            "    index index.php index.html;\n"
            "    location / { try_files $uri $uri/ /index.php?$query_string; }\n"
            "    location ~ \\.php$ {\n"
            "        include snippets/fastcgi-php.conf;\n"
            f"        fastcgi_pass unix:{socket_path};\n"
            "    }\n"
            "    location ~ /\\.(?!well-known) { deny all; }\n"
            "}\n"
    )
    NGINX_ENABLED_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=NGINX_AVAILABLE_DIR, delete=False) as temporary:
        temporary.write(config)
        temporary_path = Path(temporary.name)
    temporary_path.chmod(0o644)
    temporary_path.replace(available)
    created_link = False
    if not enabled.exists() and not enabled.is_symlink():
        enabled.symlink_to(available)
        created_link = True
    try:
        validate_nginx()
    except Exception:
        if created_link and enabled.is_symlink():
            enabled.unlink()
        if previous_config is None:
            available.unlink(missing_ok=True)
        else:
            available.write_text(previous_config, encoding="utf-8")
        if previous_pool is None:
            pool_file.unlink(missing_ok=True)
        else:
            pool_file.write_text(previous_pool, encoding="utf-8")
        for old_path, old_text in old_pool_text.items():
            old_path.write_text(old_text, encoding="utf-8")
        reload_php(php_unit)
        raise
    for old_path in old_pool_files:
        old_path.unlink(missing_ok=True)
        old_version = old_path.parts[3]
        old_unit = f"php{old_version}-fpm"
        if old_unit != php_unit:
            reload_php(old_unit)
    return {"domain": domain, "document_root": str(root)}


def website_aliases(data):
    """Rewrite server_name in a managed site config to primary domain + aliases."""
    domain = require_domain(data.get("domain"))
    server_names = " ".join([domain, *require_aliases(domain, data.get("aliases"))])
    available = NGINX_AVAILABLE_DIR / f"{domain}.conf"
    if not available.is_file():
        raise OperationError("Chưa có cấu hình Nginx cho website.")
    previous_config = available.read_text(encoding="utf-8")
    if "managed-by-neopanel" not in previous_config:
        raise OperationError("Cấu hình Nginx không thuộc NeoPanel.")
    config, count = re.subn(r"(?m)^(\s*)server_name\s+[^;]*;", lambda m: f"{m.group(1)}server_name {server_names};", previous_config)
    if not count:
        raise OperationError("Không tìm thấy server_name trong cấu hình Nginx.")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=NGINX_AVAILABLE_DIR, delete=False) as temporary:
        temporary.write(config)
        temporary_path = Path(temporary.name)
    temporary_path.chmod(0o644)
    temporary_path.replace(available)
    try:
        validate_nginx()
    except Exception:
        available.write_text(previous_config, encoding="utf-8")
        try:
            validate_nginx()
        except Exception:
            pass
        raise
    return {"domain": domain, "server_names": server_names.split()}


def _find_bind_tool(name):
    for directory in ("/usr/bin", "/usr/sbin"):
        candidate = Path(directory) / name
        if candidate.is_file():
            return str(candidate)
    return None


def _zone_line(record, domain):
    rtype = record.get("type")
    name = record.get("name")
    value = record.get("value")
    if rtype not in DNS_TYPES or not isinstance(name, str) or not DNS_NAME_RE.fullmatch(name):
        raise OperationError("Bản ghi DNS không hợp lệ.")
    if not isinstance(value, str) or not value or len(value) > 2000 or any(ord(c) < 32 for c in value):
        raise OperationError("Giá trị bản ghi DNS không hợp lệ.")
    ttl = record.get("ttl", 3600)
    if not isinstance(ttl, int) or isinstance(ttl, bool) or not 60 <= ttl <= 86400:
        raise OperationError("TTL phải từ 60 đến 86400 giây.")
    if rtype == "A":
        if ipaddress.ip_address(value).version != 4:
            raise OperationError("Bản ghi A cần địa chỉ IPv4.")
        data = value
    elif rtype == "AAAA":
        if ipaddress.ip_address(value).version != 6:
            raise OperationError("Bản ghi AAAA cần địa chỉ IPv6.")
        data = value
    elif rtype in {"CNAME", "NS", "MX"}:
        target = value.rstrip(".")
        if not DOMAIN_RE.fullmatch(target):
            raise OperationError("Giá trị phải là tên miền hợp lệ.")
        data = target + "."
        if rtype == "MX":
            priority = record.get("priority")
            if not isinstance(priority, int) or isinstance(priority, bool) or not 0 <= priority <= 65535:
                raise OperationError("MX cần độ ưu tiên từ 0 đến 65535.")
            data = f"{priority} {data}"
    elif rtype == "TXT":
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        data = " ".join(f'"{escaped[i:i + 255]}"' for i in range(0, len(escaped), 255))
    else:
        # SRV / CAA are passed through only if they are plain printable tokens.
        if not re.fullmatch(r'[A-Za-z0-9_. "-]+', value):
            raise OperationError("Giá trị bản ghi không hợp lệ.")
        data = value
    return f"{name} {ttl} IN {rtype} {data}\n"


def dns_zone_write(data):
    """Render the full BIND zone for a domain from the panel's record list."""
    domain = require_domain(data.get("domain"))
    records = data.get("records")
    if not isinstance(records, list) or len(records) > 500:
        raise OperationError("Danh sách bản ghi DNS không hợp lệ.")
    body = "".join(_zone_line(item, domain) for item in records if isinstance(item, dict))
    checkzone = _find_bind_tool("named-checkzone")
    rndc = _find_bind_tool("rndc")
    if not checkzone or not rndc or not Path("/etc/bind").is_dir():
        return {"domain": domain, "applied": False, "reason": "BIND9 chưa được cài trên máy chủ."}
    has_ns = any(item.get("type") == "NS" and item.get("name") == "@" for item in records if isinstance(item, dict))
    header = (
        "; managed-by-neopanel\n"
        "$TTL 3600\n"
        f"@ IN SOA ns1.{domain}. hostmaster.{domain}. ({int(time.time())} 7200 3600 1209600 3600)\n"
    )
    if not has_ns:
        header += f"@ IN NS ns1.{domain}.\n"
    BIND_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    zone_file = BIND_DIR / f"db.{domain}"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=BIND_DIR, delete=False, suffix=".tmp") as temporary:
        temporary.write(header + body)
        temporary_path = Path(temporary.name)
    try:
        run([checkzone, domain, str(temporary_path)])
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise OperationError("BIND từ chối bản ghi DNS (named-checkzone lỗi).")
    temporary_path.chmod(0o644)
    temporary_path.replace(zone_file)
    zones = sorted(path.name[3:] for path in BIND_DIR.glob("db.*"))
    conf = "// managed-by-neopanel\n" + "".join(
        f'zone "{name}" {{ type master; file "{BIND_DIR}/db.{name}"; }};\n' for name in zones
    )
    (BIND_DIR / "zones.conf").write_text(conf, encoding="utf-8")
    run([rndc, "reconfig"])
    run([rndc, "reload", domain])
    return {"domain": domain, "applied": True}


def website_toggle(data, enabled):
    domain = require_domain(data.get("domain"))
    available = NGINX_AVAILABLE_DIR / f"{domain}.conf"
    site_link = NGINX_ENABLED_DIR / f"neopanel-{domain}.conf"
    if enabled:
        if not available.is_file():
            raise OperationError("Chưa có cấu hình Nginx cho website.")
        NGINX_ENABLED_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
        if site_link.is_symlink():
            if site_link.resolve(strict=True) != available.resolve(strict=True):
                raise OperationError("Cấu hình Nginx đang trỏ tới tệp không được quản lý.")
        elif site_link.exists():
            raise OperationError("Đã có một cấu hình Nginx cùng tên không thuộc NeoPanel.")
        else:
            site_link.symlink_to(available)
    elif site_link.is_symlink():
        try:
            if site_link.resolve(strict=True) != available.resolve(strict=True):
                raise OperationError("Cấu hình Nginx đang trỏ tới tệp không được quản lý.")
        except FileNotFoundError:
            pass
        site_link.unlink()
    try:
        validate_nginx()
    except Exception:
        if enabled and site_link.is_symlink():
            site_link.unlink()
        elif not enabled and available.exists() and not site_link.exists():
            site_link.symlink_to(available)
        raise
    return {"domain": domain, "enabled": enabled}


def website_delete(data):
    domain = require_domain(data.get("domain"))
    available = NGINX_AVAILABLE_DIR / f"{domain}.conf"
    site_link = NGINX_ENABLED_DIR / f"neopanel-{domain}.conf"
    if available.exists() and "managed-by-neopanel" not in available.read_text(encoding="utf-8"):
        raise OperationError("Cấu hình Nginx không thuộc NeoPanel; không xóa.")
    if site_link.exists() or site_link.is_symlink():
        if not site_link.is_symlink():
            raise OperationError("Mục Nginx cùng tên không thuộc NeoPanel; không xóa.")
        try:
            if site_link.resolve(strict=True) != available.resolve(strict=True):
                raise OperationError("Liên kết Nginx không thuộc NeoPanel; không xóa.")
        except FileNotFoundError as exc:
            raise OperationError("Liên kết Nginx bị hỏng; không xóa.") from exc
    was_enabled = site_link.is_symlink()
    if was_enabled:
        site_link.unlink()
    previous_config = available.read_text(encoding="utf-8") if available.exists() else None
    try:
        validate_nginx()
    except Exception:
        if was_enabled and not site_link.exists():
            site_link.symlink_to(available)
        raise
    available.unlink(missing_ok=True)
    return {"domain": domain, "files_preserved": True}


def database_create(data):
    name = data.get("name")
    username = data.get("username")
    password = data.get("password")
    if not isinstance(name, str) or not IDENTIFIER_RE.fullmatch(name):
        raise OperationError("Tên database không hợp lệ.")
    if not isinstance(username, str) or not IDENTIFIER_RE.fullmatch(username):
        raise OperationError("Tên database user không hợp lệ.")
    if not isinstance(password, str) or not 8 <= len(password) <= 128 or any(not 32 <= ord(c) < 127 for c in password):
        raise OperationError("Mật khẩu database phải dài 8–128 ký tự ASCII hiển thị được.")
    sql_password = password.replace("\\", "\\\\").replace("'", "''")
    sql = (
        f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n"
        f"CREATE USER '{username}'@'localhost' IDENTIFIED BY '{sql_password}';\n"
        f"GRANT ALL PRIVILEGES ON `{name}`.* TO '{username}'@'localhost';\n"
        "FLUSH PRIVILEGES;\n"
    )
    run(["/usr/bin/mariadb"], input_text=sql)
    return {"name": name, "username": username, "host": "localhost"}
    
def database_delete(data):
    name = data.get("name")
    username = data.get("username")
    if not isinstance(name, str) or not IDENTIFIER_RE.fullmatch(name):
        raise OperationError("Tên database không hợp lệ.")
    if not isinstance(username, str) or not IDENTIFIER_RE.fullmatch(username):
        raise OperationError("Tên database user không hợp lệ.")
    sql = f"DROP DATABASE `{name}`;\nDROP USER '{username}'@'localhost';\nFLUSH PRIVILEGES;\n"
    run(["/usr/bin/mariadb"], input_text=sql)
    return {"name": name, "deleted": True}


def certificate_issue(data):
    domain = require_domain(data.get("domain"))
    email = data.get("email")
    if not isinstance(email, str) or len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise OperationError("Email ACME không hợp lệ.")
    run(
        ["/usr/bin/certbot", "--nginx", "--non-interactive", "--agree-tos", "--redirect", "--email", email, "-d", domain],
        timeout=840,
    )
    certificate = Path("/etc/letsencrypt/live") / domain / "cert.pem"
    output = run(["/usr/bin/openssl", "x509", "-noout", "-dates", "-in", str(certificate)])
    dates = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    expires = datetime.strptime(dates["notAfter"], "%b %d %H:%M:%S %Y %Z").isoformat() if dates.get("notAfter") else None
    return {"domain": domain, "issued": True, "expires_at": expires}


def service_status(data):
    name = data.get("name")
    allowed = {"nginx", "mariadb", "neopanel"}
    if name not in allowed and not (isinstance(name, str) and re.fullmatch(r"php[0-9]{1,2}\.[0-9]{1,2}-fpm", name)):
        raise OperationError("Dịch vụ không nằm trong danh sách cho phép.")
    result = subprocess.run(["/usr/bin/systemctl", "is-active", name], capture_output=True, text=True, check=False)
    return {"name": name, "status": result.stdout.strip() or "unknown"}


def php_versions(_data):
    versions = sorted({path.parent.parent.name for path in Path("/etc/php").glob("*/fpm/php-fpm.conf") if shutil.which(f"php-fpm{path.parent.parent.name}")})
    return {"versions": versions}


PHP_CONFIG_MAX_BYTES = 2 * 1024 * 1024
PHP_CUSTOM_INI = "fpm/conf.d/99-neopanel-custom.ini"
PHP_CONFIG_REL_RE = re.compile(
    r"(?:fpm/php\.ini|cli/php\.ini|fpm/php-fpm\.conf|"
    r"(?:fpm|cli)/conf\.d/[A-Za-z0-9][A-Za-z0-9._-]{0,80}\.ini)\Z"
)
PHP_CUSTOM_INI_TEMPLATE = (
    "; managed-by-neopanel\n"
    "; Tùy chỉnh PHP-FPM cho phiên bản này. Giá trị tại đây ghi đè php.ini.\n"
    "; Ví dụ:\n"
    "; memory_limit = 256M\n"
    "; upload_max_filesize = 64M\n"
    "; post_max_size = 64M\n"
    "; max_execution_time = 60\n"
)


def require_installed_php(version):
    if not isinstance(version, str) or not PHP_RE.fullmatch(version):
        raise OperationError("Phiên bản PHP không hợp lệ.")
    root = Path("/etc/php") / version
    if not (root / "fpm/php-fpm.conf").is_file() or not shutil.which(f"php-fpm{version}"):
        raise OperationError(f"PHP-FPM {version} chưa được cài đặt.")
    return version, root


def resolve_php_config(version, relative, *, allow_missing=False):
    version, root = require_installed_php(version)
    if not isinstance(relative, str) or not PHP_CONFIG_REL_RE.fullmatch(relative):
        raise OperationError("Tệp cấu hình PHP không nằm trong danh sách cho phép.")
    root_real = root.resolve()
    candidate = root / relative
    if candidate.exists() or candidate.is_symlink():
        try:
            target = candidate.resolve(strict=True)
        except OSError as exc:
            raise OperationError("Không tìm thấy tệp cấu hình.") from exc
        try:
            target.relative_to(root_real)
        except ValueError as exc:
            raise OperationError("Đường dẫn cấu hình PHP không hợp lệ.") from exc
        if not target.is_file() or target.is_symlink():
            raise OperationError("Tệp cấu hình PHP không hợp lệ.")
        return version, target, relative
    if allow_missing and relative == PHP_CUSTOM_INI:
        conf_dir = (root / "fpm/conf.d").resolve()
        try:
            conf_dir.relative_to(root_real)
        except ValueError as exc:
            raise OperationError("Thư mục conf.d không hợp lệ.") from exc
        return version, conf_dir / Path(relative).name, relative
    raise OperationError("Không tìm thấy tệp cấu hình.")


def php_config_list(data):
    version, root = require_installed_php(data.get("version"))
    files = []
    seen = set()
    core = [
        ("fpm/php.ini", "php.ini (PHP-FPM)"),
        ("cli/php.ini", "php.ini (CLI)"),
        ("fpm/php-fpm.conf", "php-fpm.conf"),
        (PHP_CUSTOM_INI, "99-neopanel-custom.ini (tùy chỉnh FPM)"),
    ]
    for relative, label in core:
        path = root / relative
        files.append({"path": relative, "label": label, "exists": path.is_file()})
        seen.add(relative)
    conf_d = root / "fpm/conf.d"
    if conf_d.is_dir():
        for path in sorted(conf_d.iterdir()):
            relative = f"fpm/conf.d/{path.name}"
            if relative in seen or not PHP_CONFIG_REL_RE.fullmatch(relative):
                continue
            if not path.is_file() and not path.is_symlink():
                continue
            files.append({"path": relative, "label": path.name, "exists": True})
    return {"version": version, "files": files}


def php_config_read(data):
    relative = data.get("path")
    version, target, relative = resolve_php_config(data.get("version"), relative, allow_missing=True)
    if not target.is_file():
        return {"version": version, "path": relative, "content": PHP_CUSTOM_INI_TEMPLATE, "exists": False}
    if target.stat().st_size > PHP_CONFIG_MAX_BYTES:
        raise OperationError("Tệp cấu hình quá lớn để sửa trên giao diện.")
    try:
        content = target.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise OperationError("Tệp cấu hình không phải văn bản UTF-8.") from exc
    return {"version": version, "path": relative, "content": content, "exists": True}


def php_config_write(data):
    relative = data.get("path")
    content = data.get("content")
    version, target, relative = resolve_php_config(data.get("version"), relative, allow_missing=True)
    if not isinstance(content, str):
        raise OperationError("Nội dung cấu hình không hợp lệ.")
    content = content.replace("\r\n", "\n").replace("\r", "\n")
    if "\x00" in content:
        raise OperationError("Nội dung cấu hình không hợp lệ.")
    encoded = content.encode("utf-8")
    if len(encoded) > PHP_CONFIG_MAX_BYTES:
        raise OperationError("Tệp cấu hình vượt giới hạn 2 MB.")
    previous = target.read_text(encoding="utf-8") if target.is_file() else None
    created = previous is None
    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=target.parent, delete=False) as temporary:
        temporary.write(content)
        if not content.endswith("\n"):
            temporary.write("\n")
        temporary_path = Path(temporary.name)
    temporary_path.chmod(target.stat().st_mode if target.is_file() else 0o644)
    temporary_path.replace(target)
    php_executable = shutil.which(f"php-fpm{version}")
    try:
        if relative != "cli/php.ini":
            if not php_executable:
                raise OperationError(f"PHP-FPM {version} chưa được cài đặt.")
            run([php_executable, "-t"])
            reload_php(f"php{version}-fpm")
        else:
            cli = shutil.which(f"php{version}")
            if cli:
                run([cli, "-c", str(target), "-r", "echo 1;"])
    except Exception:
        if created:
            target.unlink(missing_ok=True)
        elif previous is not None:
            target.write_text(previous, encoding="utf-8")
        try:
            if relative != "cli/php.ini" and php_executable:
                reload_php(f"php{version}-fpm")
        except Exception:
            pass
        raise OperationError("Cấu hình PHP không hợp lệ hoặc không nạp lại được PHP-FPM. Đã hoàn tác thay đổi.")
    return {"version": version, "path": relative, "reloaded": relative != "cli/php.ini"}


def backup_website(data):
    domain = require_domain(data.get("domain"))
    root = require_document_root(domain, data.get("document_root"))
    if not root.is_dir():
        raise OperationError("Thư mục website chưa tồn tại.")
    BACKUP_ROOT.mkdir(mode=0o750, parents=True, exist_ok=True)
    stamp = subprocess.run(["/bin/date", "+%Y%m%dT%H%M%SZ"], capture_output=True, text=True, check=True).stdout.strip()
    target = BACKUP_ROOT / f"{domain}-{stamp}.tar.gz"
    run(["/bin/tar", "-czf", str(target), "-C", str(WEB_ROOT), domain], timeout=840)
    os.chown(target, 0, 33)
    digest = file_checksum(target)
    return {"file_path": str(target), "size_bytes": target.stat().st_size, "checksum": digest}


def file_checksum(path):
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def backup_database(data):
    name = data.get("name")
    if not isinstance(name, str) or not IDENTIFIER_RE.fullmatch(name):
        raise OperationError("Tên database không hợp lệ.")
    BACKUP_ROOT.mkdir(mode=0o750, parents=True, exist_ok=True)
    stamp = subprocess.run(["/bin/date", "+%Y%m%dT%H%M%SZ"], capture_output=True, text=True, check=True).stdout.strip()
    target = BACKUP_ROOT / f"{name}-{stamp}.sql.gz"
    with target.open("wb") as raw_output:
        process = subprocess.Popen(["/usr/bin/mariadb-dump", "--single-transaction", "--routines", "--events", name], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            with gzip.GzipFile(fileobj=raw_output, mode="wb") as compressed:
                shutil.copyfileobj(process.stdout, compressed)
            result = process.wait(timeout=840)
        except Exception:
            process.kill()
            target.unlink(missing_ok=True)
            raise
    if result:
        target.unlink(missing_ok=True)
        raise OperationError("Không thể tạo bản sao lưu database.")
    os.chown(target, 0, 33)
    os.chmod(target, 0o640)
    return {"file_path": str(target), "size_bytes": target.stat().st_size, "checksum": file_checksum(target)}


def backup_delete(data):
    filename = data.get("filename")
    if not isinstance(filename, str) or not re.fullmatch(r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,63}-[0-9]{8}T[0-9]{6}Z\.tar\.gz", filename):
        raise OperationError("Chỉ được xóa bản sao lưu website hợp lệ.")
    target = BACKUP_ROOT / filename
    if target.parent.resolve() != BACKUP_ROOT.resolve() or target.is_symlink() or not target.is_file():
        raise OperationError("Không tìm thấy bản sao lưu hợp lệ.")
    target.unlink()
    return {"deleted": True}


def restore_database(data):
    name = data.get("name")
    filename = data.get("filename")
    if not isinstance(name, str) or not IDENTIFIER_RE.fullmatch(name):
        raise OperationError("Tên database không hợp lệ.")
    path = (BACKUP_ROOT / str(filename)).resolve()
    if path.parent != BACKUP_ROOT.resolve() or not re.fullmatch(re.escape(name) + r"-[0-9]{8}T[0-9]{6}Z\.sql\.gz", str(filename)):
        raise OperationError("Tệp database backup không hợp lệ.")
    if not path.is_file() or (data.get("checksum") and file_checksum(path) != data["checksum"]):
        raise OperationError("Checksum backup không khớp hoặc tệp không tồn tại.")
    source = gzip.open(path, "rb")
    process = subprocess.Popen(["/usr/bin/mariadb", name], stdin=source, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        result = process.wait(timeout=840)
    except Exception:
        process.kill()
        raise OperationError("Phục hồi database quá thời gian cho phép.")
    finally:
        source.close()
    if result:
        raise OperationError("Không thể phục hồi database từ bản sao lưu.")
    return {"name": name, "restored": True}


def restore_website(data):
    domain = require_domain(data.get("domain"))
    archive_path = Path(data.get("file_path", "")).resolve()
    if archive_path.parent != BACKUP_ROOT.resolve() or archive_path.name != data.get("filename"):
        raise OperationError("Đường dẫn bản sao lưu không hợp lệ.")
    if not re.fullmatch(re.escape(domain) + r"-[0-9]{8}T[0-9]{6}Z\.tar\.gz", archive_path.name):
        raise OperationError("Bản sao lưu không thuộc website đã chọn.")
    if not archive_path.is_file() or (data.get("checksum") and file_checksum(archive_path) != data["checksum"]):
        raise OperationError("Checksum backup không khớp hoặc tệp không tồn tại.")
    root_real = WEB_ROOT.resolve()
    owner_uid, web_gid = site_owner(domain)
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            item = Path(member.name)
            if item.is_absolute() or ".." in item.parts or not item.parts or item.parts[0] != domain:
                raise OperationError("Bản sao lưu chứa đường dẫn ngoài phạm vi website.")
            if not (member.isfile() or member.isdir()):
                raise OperationError("Bản sao lưu chứa loại tệp không được hỗ trợ.")
        for member in members:
            relative = Path(member.name)
            target = (WEB_ROOT / relative).resolve()
            if not target.is_relative_to(root_real):
                raise OperationError("Đường dẫn phục hồi vượt khỏi thư mục website.")
            if member.isdir():
                target.mkdir(mode=0o750, parents=True, exist_ok=True)
                os.chown(target, owner_uid, web_gid)
                os.chmod(target, 0o750)
                continue
            target.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
            os.chown(target.parent, owner_uid, web_gid)
            os.chmod(target.parent, 0o750)
            # Reject symlinked parents to prevent extraction through an existing link.
            current = target.parent
            while current != root_real:
                if current.is_symlink():
                    raise OperationError("Phát hiện symbolic link trong đường dẫn phục hồi.")
                current = current.parent
            source = archive.extractfile(member)
            if source is None:
                raise OperationError("Không thể đọc nội dung bản sao lưu.")
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
            os.chown(target, owner_uid, web_gid)
            os.chmod(target, 0o640)
    return {"domain": domain, "restored": True}


def file_write(data):
    import base64

    domain = require_domain(data.get("domain"))
    relative = Path(data.get("path", ""))
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise OperationError("Đường dẫn tệp không hợp lệ.")
    root = (WEB_ROOT / domain).resolve()
    target = (root / relative).resolve()
    if not target.is_relative_to(root) or len(data.get("content", "")) > 140_000_000:
        raise OperationError("Tệp vượt giới hạn hoặc nằm ngoài document root.")
    owner_uid, web_gid = site_owner(domain)
    content = base64.b64decode(data["content"], validate=True)
    if len(content) > 100 * 1024 * 1024:
        raise OperationError("Kích thước tối đa mỗi tệp là 100 MB.")
    target.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(target.parent, owner_uid, web_gid)
    os.chmod(target.parent, 0o750)
    target.write_bytes(content)
    os.chown(target, owner_uid, web_gid)
    os.chmod(target, 0o640)
    return {"path": str(relative), "size_bytes": len(content)}


def file_mkdir(data):
    domain = require_domain(data.get("domain"))
    relative = Path(data.get("path", ""))
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise OperationError("Đường dẫn thư mục không hợp lệ.")
    root = (WEB_ROOT / domain).resolve()
    target = (root / relative).resolve()
    if not target.is_relative_to(root):
        raise OperationError("Thư mục nằm ngoài document root.")
    owner_uid, web_gid = site_owner(domain)
    target.mkdir(mode=0o750, parents=True, exist_ok=False)
    os.chown(target, owner_uid, web_gid)
    os.chmod(target, 0o750)
    return {"path": str(relative), "created": True}


def file_delete(data):
    domain = require_domain(data.get("domain"))
    relative = Path(data.get("path", ""))
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise OperationError("Đường dẫn tệp không hợp lệ.")
    root = (WEB_ROOT / domain).resolve()
    candidate = root / relative
    if candidate.is_symlink():
        candidate.unlink()
        return {"deleted": True}
    target = candidate.resolve()
    if not target.is_relative_to(root) or target == root:
        raise OperationError("Không được xóa document root hoặc đường dẫn ngoài phạm vi.")
    if target.is_dir():
        if data.get("recursive") is True:
            shutil.rmtree(target)
        else:
            target.rmdir()
    elif target.is_file():
        target.unlink()
    else:
        raise OperationError("Không tìm thấy tệp hoặc thư mục.")
    return {"deleted": True}


def file_rename(data):
    domain = require_domain(data.get("domain"))
    source_rel = Path(data.get("source", ""))
    target_rel = Path(data.get("target", ""))
    if any(path.is_absolute() or ".." in path.parts or not path.parts for path in (source_rel, target_rel)):
        raise OperationError("Đường dẫn đổi tên không hợp lệ.")
    root = (WEB_ROOT / domain).resolve()
    source = (root / source_rel).resolve()
    target = (root / target_rel).resolve()
    if not source.is_relative_to(root) or not target.is_relative_to(root) or not source.exists():
        raise OperationError("Nguồn hoặc đích nằm ngoài document root.")
    if target.exists():
        raise OperationError("Đã có mục cùng tên ở vị trí đích.")
    source.rename(target)
    return {"renamed": True}


def _site_root(data):
    domain = require_domain(data.get("domain"))
    return domain, (WEB_ROOT / domain).resolve()


def _rel(value, *, allow_empty=False):
    relative = Path(value if isinstance(value, str) else "")
    if relative.is_absolute() or ".." in relative.parts or (not relative.parts and not allow_empty):
        raise OperationError("Đường dẫn không hợp lệ.")
    return relative


def _chown_tree(path, uid, gid):
    entries = [path]
    if path.is_dir() and not path.is_symlink():
        entries += list(path.rglob("*"))
    for entry in entries:
        if entry.is_symlink():
            continue
        os.chown(entry, uid, gid)
        os.chmod(entry, 0o750 if entry.is_dir() else 0o640)


def file_read(data):
    import base64

    domain, root = _site_root(data)
    target = (root / _rel(data.get("path"))).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        raise OperationError("Không tìm thấy tệp.")
    if target.stat().st_size > 2 * 1024 * 1024:
        raise OperationError("Tệp lớn hơn 2 MB, không thể sửa trực tiếp.")
    return {"content": base64.b64encode(target.read_bytes()).decode("ascii")}


def file_copy(data):
    domain, root = _site_root(data)
    source = (root / _rel(data.get("source"))).resolve()
    target = (root / _rel(data.get("target"))).resolve()
    if not source.is_relative_to(root) or not target.is_relative_to(root) or not source.exists():
        raise OperationError("Nguồn hoặc đích nằm ngoài document root.")
    if target.exists():
        raise OperationError("Đã có mục cùng tên ở vị trí đích.")
    if source.is_dir() and (target == source or target.is_relative_to(source)):
        raise OperationError("Không thể sao chép thư mục vào chính nó.")
    owner_uid, web_gid = site_owner(domain)
    target.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if source.is_dir():
        shutil.copytree(source, target, symlinks=True)
    else:
        shutil.copy2(source, target)
    _chown_tree(target, owner_uid, web_gid)
    return {"copied": True}


def file_archive(data):
    import zipfile

    domain, root = _site_root(data)
    sources = data.get("sources")
    if not isinstance(sources, list) or not 0 < len(sources) <= 200:
        raise OperationError("Danh sách mục cần nén không hợp lệ.")
    target = (root / _rel(data.get("target"))).resolve()
    if not target.is_relative_to(root) or target.suffix.lower() != ".zip" or target.exists():
        raise OperationError("Tên tệp zip đích không hợp lệ hoặc đã tồn tại.")
    owner_uid, web_gid = site_owner(domain)
    total = 0
    try:
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
            for item in sources:
                source = (root / _rel(item)).resolve()
                if not source.is_relative_to(root) or not source.exists() or source == target:
                    raise OperationError("Mục cần nén nằm ngoài document root.")
                paths = [source] + (list(source.rglob("*")) if source.is_dir() else [])
                for path in paths:
                    if path.is_symlink() or path == target:
                        continue
                    if path.is_file():
                        total += path.stat().st_size
                        if total > 1024 ** 3:
                            raise OperationError("Dung lượng cần nén vượt quá 1 GB.")
                    archive.write(path, path.relative_to(root).as_posix())
    except Exception:
        target.unlink(missing_ok=True)
        raise
    os.chown(target, owner_uid, web_gid)
    os.chmod(target, 0o640)
    return {"archived": True, "size_bytes": target.stat().st_size}


def file_extract(data):
    import tarfile as tarlib
    import zipfile

    domain, root = _site_root(data)
    archive_path = (root / _rel(data.get("path"))).resolve()
    dest = (root / _rel(data.get("target_dir"), allow_empty=True)).resolve()
    if not archive_path.is_relative_to(root) or not archive_path.is_file() or not dest.is_relative_to(root):
        raise OperationError("Tệp nén hoặc thư mục đích nằm ngoài document root.")
    owner_uid, web_gid = site_owner(domain)
    dest.mkdir(mode=0o750, parents=True, exist_ok=True)
    limits = {"files": 0, "bytes": 0}

    def safe_target(name):
        member = Path(name)
        if member.is_absolute() or ".." in member.parts or not member.parts:
            raise OperationError("Tệp nén chứa đường dẫn không an toàn.")
        target = (dest / member).resolve()
        if not target.is_relative_to(dest):
            raise OperationError("Tệp nén chứa đường dẫn không an toàn.")
        return target

    def count(size):
        limits["files"] += 1
        limits["bytes"] += size
        if limits["files"] > 50000 or limits["bytes"] > 2 * 1024 ** 3:
            raise OperationError("Tệp nén quá lớn (tối đa 50.000 mục / 2 GB).")

    def write_stream(target, stream):
        target.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        with open(target, "wb") as output:
            shutil.copyfileobj(stream, output)

    name = archive_path.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    continue  # skip symlinks
                target = safe_target(info.filename)
                count(info.file_size)
                if info.is_dir():
                    target.mkdir(mode=0o750, parents=True, exist_ok=True)
                else:
                    with archive.open(info) as stream:
                        write_stream(target, stream)
    elif name.endswith((".tar.gz", ".tgz", ".tar")):
        with tarlib.open(archive_path) as archive:
            for member in archive:
                if not (member.isfile() or member.isdir()):
                    continue  # skip links and special files
                target = safe_target(member.name)
                count(member.size)
                if member.isdir():
                    target.mkdir(mode=0o750, parents=True, exist_ok=True)
                else:
                    stream = archive.extractfile(member)
                    if stream is not None:
                        write_stream(target, stream)
    else:
        raise OperationError("Chỉ hỗ trợ giải nén .zip, .tar.gz, .tgz, .tar.")
    _chown_tree(dest, owner_uid, web_gid)
    laravel = (dest / "artisan").is_file() and (dest / "public" / "index.php").is_file()
    return {"extracted": limits["files"], "laravel": laravel, "base": str(dest.relative_to(root)) if dest != root else ""}


def website_webroot(data):
    """Point Nginx 'root' at a sub-directory (e.g. Laravel's public/)."""
    domain, root = _site_root(data)
    subdir = require_webroot(data.get("subdir"))
    new_root = root / subdir if subdir else root
    if subdir and not (new_root.resolve().is_relative_to(root) and new_root.is_dir()):
        raise OperationError("Thư mục web gốc chưa tồn tại trong website.")
    available = NGINX_AVAILABLE_DIR / f"{domain}.conf"
    if not available.is_file():
        raise OperationError("Chưa có cấu hình Nginx cho website.")
    previous = available.read_text(encoding="utf-8")
    if "managed-by-neopanel" not in previous:
        raise OperationError("Cấu hình Nginx không thuộc NeoPanel.")
    config, count = re.subn(r"(?m)^(\s*)root\s+[^;]*;", lambda m: f"{m.group(1)}root {new_root};", previous, count=1)
    if not count:
        raise OperationError("Không tìm thấy dòng root trong cấu hình Nginx.")
    if "client_max_body_size" not in config:
        config = re.sub(r"(?m)^(\s*)(root\s)", lambda m: f"{m.group(1)}client_max_body_size 128m;\n{m.group(1)}{m.group(2)}", config, count=1)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=NGINX_AVAILABLE_DIR, delete=False) as temporary:
        temporary.write(config)
        temporary_path = Path(temporary.name)
    temporary_path.chmod(0o644)
    temporary_path.replace(available)
    try:
        validate_nginx()
    except Exception:
        available.write_text(previous, encoding="utf-8")
        try:
            validate_nginx()
        except Exception:
            pass
        raise
    return {"domain": domain, "webroot": subdir}


OPERATIONS = {
    "website_create": website_create,
    "website_aliases": website_aliases,
    "dns_zone_write": dns_zone_write,
    "website_webroot": website_webroot,
    "file_read": file_read,
    "file_copy": file_copy,
    "file_archive": file_archive,
    "file_extract": file_extract,
    "website_disable": lambda data: website_toggle(data, False),
    "website_enable": lambda data: website_toggle(data, True),
    "website_delete": website_delete,
    "database_create": database_create,
    "database_delete": database_delete,
    "certificate_issue": certificate_issue,
    "service_status": service_status,
    "php_versions": php_versions,
    "php_config_list": php_config_list,
    "php_config_read": php_config_read,
    "php_config_write": php_config_write,
    "backup_website": backup_website,
    "backup_database": backup_database,
    "backup_delete": backup_delete,
    "restore_database": restore_database,
    "restore_website": restore_website,
    "file_write": file_write,
    "file_mkdir": file_mkdir,
    "file_delete": file_delete,
    "file_rename": file_rename,
}


def main():
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    try:
        if action not in OPERATIONS:
            raise OperationError("Tác vụ không được hỗ trợ.")
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise OperationError("Dữ liệu tác vụ không hợp lệ.")
        result = OPERATIONS[action](payload)
        print(json.dumps({"ok": True, **result}))
    except Exception as exc:
        # Keep errors short and do not print command output, environment or secrets.
        message = str(exc) if isinstance(exc, OperationError) else "Tác vụ hệ thống thất bại."
        print(json.dumps({"ok": False, "error": message[:240]}))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
