from calendar import monthrange
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.audit import record_event
from app.database import get_connection, init_db
from app.system_ops import OperationError, run_operation


def advance(now: datetime, frequency: str) -> datetime:
    if frequency == "daily":
        return now + timedelta(days=1)
    if frequency == "weekly":
        return now + timedelta(days=7)
    month = now.month + 1
    year = now.year + (month - 1) // 12
    month = (month - 1) % 12 + 1
    return now.replace(year=year, month=month, day=min(now.day, monthrange(year, month)[1]))


def run_due_backups() -> None:
    now = datetime.now(timezone.utc)
    with get_connection() as conn:
        schedules = conn.execute(
            """SELECT s.*, w.domain, w.document_root FROM backup_schedules s
               JOIN websites w ON w.id = s.website_id
               WHERE s.enabled = 1 AND s.kind = 'website'
                 AND (s.next_run_at IS NULL OR s.next_run_at <= datetime('now'))
               ORDER BY s.id LIMIT 20"""
        ).fetchall()

    for schedule in schedules:
        with get_connection() as conn:
            cursor = conn.execute(
                "INSERT INTO backups (website_id, schedule_id, kind, file_path, status) VALUES (?, ?, 'website', '', 'running')",
                (schedule["website_id"], schedule["id"]),
            )
            backup_id = cursor.lastrowid
            cursor = conn.execute(
                "INSERT INTO jobs (kind, resource_type, resource_id, status, progress, message, started_at) VALUES ('website_backup_scheduled', 'backup', ?, 'running', 10, 'Đang sao lưu theo lịch', CURRENT_TIMESTAMP)",
                (backup_id,),
            )
            job_id = cursor.lastrowid

        error = None
        try:
            result = run_operation(
                "backup_website",
                {"domain": schedule["domain"], "document_root": schedule["document_root"]},
            )
            with get_connection() as conn:
                conn.execute(
                    "UPDATE backups SET status = 'completed', file_path = ?, size_bytes = ?, checksum = ? WHERE id = ?",
                    (result["file_path"], result["size_bytes"], result["checksum"], backup_id),
                )
                conn.execute("UPDATE jobs SET status = 'succeeded', progress = 100, message = 'Hoàn tất', finished_at = CURRENT_TIMESTAMP WHERE id = ?", (job_id,))
            record_event(None, "scheduled_backup_completed", resource_type="backup", resource_id=backup_id)
        except OperationError as exc:
            error = str(exc)[:240]
            with get_connection() as conn:
                conn.execute("UPDATE backups SET status = 'failed', error = ? WHERE id = ?", (error, backup_id))
                conn.execute("UPDATE jobs SET status = 'failed', error = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?", (error, job_id))
            record_event(None, "scheduled_backup_failed", resource_type="backup", resource_id=backup_id, result="failure", details={"error": error})

        next_run = advance(now, schedule["frequency"]).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")
        with get_connection() as conn:
            conn.execute("UPDATE backup_schedules SET next_run_at = ? WHERE id = ?", (next_run, schedule["id"]))
            expired = conn.execute(
                "SELECT id, file_path FROM backups WHERE schedule_id = ? AND kind = 'website' AND status = 'completed' AND created_at < datetime('now', ?)",
                (schedule["id"], f"-{schedule['retention_days']} days"),
            ).fetchall()
        for old_backup in expired:
            filename = Path(old_backup["file_path"]).name
            try:
                run_operation("backup_delete", {"filename": filename})
            except OperationError:
                continue
            with get_connection() as conn:
                conn.execute("DELETE FROM backups WHERE id = ?", (old_backup["id"],))


def main():
    init_db()
    run_due_backups()


if __name__ == "__main__":
    main()
