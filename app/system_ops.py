import json
import os
import subprocess
from pathlib import Path


HELPER_PATH = Path(
    os.environ.get("NEOPANEL_OPS_HELPER", "/usr/local/sbin/neopanel-ops")
)


class OperationError(RuntimeError):
    pass


def run_operation(action: str, payload: dict | None = None) -> dict:
    """Invoke the installed root-owned allowlist helper without a shell."""
    allowed_actions = {
        "website_create",
        "website_aliases",
        "dns_zone_write",
        "website_webroot",
        "file_read",
        "file_copy",
        "file_archive",
        "file_extract",
        "website_disable",
        "website_enable",
        "website_delete",
        "database_create",
        "database_delete",
        "certificate_issue",
        "service_status",
        "php_versions",
        "php_config_list",
        "php_config_read",
        "php_config_write",
        "backup_website",
        "backup_database",
        "backup_delete",
        "restore_website",
        "restore_database",
        "file_write",
        "file_mkdir",
        "file_delete",
        "file_rename",
    }
    if action not in allowed_actions:
        raise OperationError("Tác vụ hệ thống không được cho phép.")

    try:
        result = subprocess.run(
            ["sudo", "-n", str(HELPER_PATH), action],
            input=json.dumps(payload or {}),
            capture_output=True,
            text=True,
        timeout=900 if action in {"certificate_issue", "backup_website", "backup_database", "restore_website", "restore_database", "file_extract", "file_archive", "file_write", "file_copy"} else 60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OperationError("Không thể kết nối helper quản trị máy chủ.") from exc

    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise OperationError("Helper trả về kết quả không hợp lệ.") from exc

    if result.returncode != 0 or not response.get("ok"):
        # Do not pass raw stderr back to the browser; it may contain secrets.
        raise OperationError(response.get("error", "Tác vụ hệ thống thất bại."))
    return response
