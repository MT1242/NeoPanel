
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "neopanel.db"


def get_connection():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin',
                is_active INTEGER NOT NULL DEFAULT 1,
                session_version INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS websites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL COLLATE NOCASE UNIQUE,
                document_root TEXT NOT NULL,
                php_version TEXT NOT NULL DEFAULT '8.1',
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'active', 'disabled', 'failed')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Upgrade databases created by the first NeoPanel prototype. SQLite
        # cannot alter a CHECK constraint, so rebuild only this small table.
        table_sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'websites'"
        ).fetchone()[0]
        if "'failed'" not in table_sql.lower():
            conn.execute("ALTER TABLE websites RENAME TO websites_legacy")
            conn.execute("""
                CREATE TABLE websites (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    document_root TEXT NOT NULL,
                    php_version TEXT NOT NULL DEFAULT '8.1',
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'active', 'disabled', 'failed')),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                INSERT INTO websites (id, domain, document_root, php_version, status, created_at)
                SELECT id, domain, document_root, php_version, status, created_at
                FROM websites_legacy
            """)
            conn.execute("DROP TABLE websites_legacy")

        if "public_dir" not in {row[1] for row in conn.execute("PRAGMA table_info(websites)")}:
            conn.execute("ALTER TABLE websites ADD COLUMN public_dir TEXT NOT NULL DEFAULT ''")

        conn.executescript("""
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website_id INTEGER NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
                domain TEXT NOT NULL COLLATE NOCASE UNIQUE,
                is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
                dns_status TEXT NOT NULL DEFAULT 'unchecked'
                    CHECK (dns_status IN ('unchecked', 'valid', 'invalid', 'unknown')),
                checked_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS dns_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                type TEXT NOT NULL CHECK (type IN ('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA')),
                value TEXT NOT NULL,
                priority INTEGER,
                ttl INTEGER NOT NULL DEFAULT 3600,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS hosting_databases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website_id INTEGER REFERENCES websites(id) ON DELETE SET NULL,
                name TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                host TEXT NOT NULL DEFAULT 'localhost',
                secret_ref TEXT,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'active', 'failed', 'deleted')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS ssl_certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website_id INTEGER NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
                domain TEXT NOT NULL,
                issuer TEXT,
                issued_at TEXT,
                expires_at TEXT,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'active', 'expired', 'failed', 'revoked')),
                last_error TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website_id INTEGER REFERENCES websites(id) ON DELETE SET NULL,
                database_id INTEGER REFERENCES hosting_databases(id) ON DELETE SET NULL,
                schedule_id INTEGER REFERENCES backup_schedules(id) ON DELETE SET NULL,
                kind TEXT NOT NULL CHECK (kind IN ('website', 'database', 'full')),
                file_path TEXT NOT NULL,
                size_bytes INTEGER NOT NULL DEFAULT 0,
                checksum TEXT,
                status TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'running', 'completed', 'failed', 'restoring')),
                error TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                resource_type TEXT,
                resource_id INTEGER,
                requested_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                status TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
                progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
                message TEXT,
                error TEXT,
                payload_json TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                started_at TEXT,
                finished_at TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                username TEXT,
                action TEXT NOT NULL,
                resource_type TEXT,
                resource_id TEXT,
                result TEXT NOT NULL DEFAULT 'success'
                    CHECK (result IN ('success', 'failure', 'warning')),
                details TEXT,
                ip_address TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT,
                succeeded INTEGER NOT NULL DEFAULT 0 CHECK (succeeded IN (0, 1)),
                attempted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS roles (
                name TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS permissions (
                name TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS role_permissions (
                role_name TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
                permission_name TEXT NOT NULL REFERENCES permissions(name) ON DELETE CASCADE,
                PRIMARY KEY (role_name, permission_name)
            );

            CREATE TABLE IF NOT EXISTS user_websites (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                website_id INTEGER NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
                granted_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, website_id)
            );

            CREATE TABLE IF NOT EXISTS backup_schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website_id INTEGER REFERENCES websites(id) ON DELETE CASCADE,
                kind TEXT NOT NULL CHECK (kind IN ('website', 'database', 'full')),
                frequency TEXT NOT NULL CHECK (frequency IN ('daily', 'weekly', 'monthly')),
                retention_days INTEGER NOT NULL DEFAULT 30 CHECK (retention_days BETWEEN 1 AND 3650),
                enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
                next_run_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cpu_percent REAL,
                memory_percent REAL,
                memory_used_bytes INTEGER,
                memory_total_bytes INTEGER,
                disk_percent REAL,
                disk_used_bytes INTEGER,
                disk_total_bytes INTEGER,
                load_1m REAL,
                uptime_seconds INTEGER,
                collected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_websites_status ON websites(status);
            CREATE INDEX IF NOT EXISTS idx_domains_website ON domains(website_id);
            CREATE INDEX IF NOT EXISTS idx_user_websites_website ON user_websites(website_id);
            CREATE INDEX IF NOT EXISTS idx_jobs_status_created ON jobs(status, created_at);
            CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_login_attempts_user_time
                ON login_attempts(username, attempted_at DESC);
            CREATE INDEX IF NOT EXISTS idx_metrics_collected ON system_metrics(collected_at DESC);
        """)

        user_columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
        if "session_version" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")

        job_columns = {row["name"] for row in conn.execute("PRAGMA table_info(jobs)")}
        if "payload_json" not in job_columns:
            conn.execute("ALTER TABLE jobs ADD COLUMN payload_json TEXT")
        backup_columns = {row["name"] for row in conn.execute("PRAGMA table_info(backups)")}
        if "database_id" not in backup_columns:
            conn.execute("ALTER TABLE backups ADD COLUMN database_id INTEGER REFERENCES hosting_databases(id) ON DELETE SET NULL")
        if "schedule_id" not in backup_columns:
            conn.execute("ALTER TABLE backups ADD COLUMN schedule_id INTEGER REFERENCES backup_schedules(id) ON DELETE SET NULL")

        conn.executemany(
            "INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)",
            [
                ("super_admin", "Quản trị toàn bộ máy chủ"),
                ("hosting_admin", "Quản lý tài nguyên hosting"),
                ("website_manager", "Quản lý website được phân công"),
                ("read_only", "Chỉ xem dữ liệu được phép"),
            ],
        )

        permission_names = [
            "websites.read", "websites.create", "websites.update", "websites.delete", "jobs.read",
            "domains.read", "domains.add_domain", "domains.check_dns", "domains.remove_domain",
            "dns.read", "dns.add_record", "dns.delete_record",
            "databases.read", "databases.create_database", "databases.delete_database",
            "php.read", "php.assign_php", "php.save_config", "ssl.read", "ssl.issue_certificate",
            "files.read", "files.upload_file", "files.create_directory", "files.delete_file", "files.rename_file", "files.create_file", "files.save_file", "files.move_file", "files.copy_file", "files.archive_file", "files.extract_file", "files.set_webroot", "files.bulk_archive", "files.bulk_delete", "files.bulk_move", "files.bulk_copy",
            "services.read", "monitoring.read", "backups.read", "backups.create_backup", "backups.restore_backup",
            "backups.create_schedule", "backups.create_database_backup", "backups.manage_schedule", "logs.read", "users.read", "users.create_user", "users.manage_user", "users.toggle_user",
            "settings.read", "settings.save_settings",
        ]
        conn.executemany(
            "INSERT OR IGNORE INTO permissions (name) VALUES (?)",
            [(name,) for name in permission_names],
        )
        all_permissions = [("super_admin", name) for name in permission_names]
        hosting_permissions = [name for name in permission_names if name.split(".", 1)[0] in {
            "websites", "domains", "dns", "databases", "php", "ssl", "backups", "services", "monitoring", "logs", "files", "jobs"
        }]
        read_permissions = [name for name in permission_names if name.endswith(".read")]
        manager_permissions = [name for name in permission_names if name in {"websites.read", "domains.read", "files.read"}]
        conn.executemany("INSERT OR IGNORE INTO role_permissions (role_name, permission_name) VALUES (?, ?)", all_permissions)
        conn.executemany("INSERT OR IGNORE INTO role_permissions (role_name, permission_name) VALUES (?, ?)", [("hosting_admin", name) for name in hosting_permissions])
        conn.executemany("INSERT OR IGNORE INTO role_permissions (role_name, permission_name) VALUES (?, ?)", [("read_only", name) for name in read_permissions])
        conn.executemany("INSERT OR IGNORE INTO role_permissions (role_name, permission_name) VALUES (?, ?)", [("website_manager", name) for name in manager_permissions])

