#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run this installer with sudo." >&2
  exit 1
fi

if [[ $# -ne 2 || ! $1 =~ ^[a-z_][a-z0-9_-]*$ || ! $2 =~ ^/[A-Za-z0-9_./-]+$ || $2 == *..* ]]; then
  echo "Usage: sudo $0 <neopanel-service-user> <absolute-app-directory>" >&2
  exit 2
fi

service_user=$1
app_dir=$2
id "$service_user" >/dev/null
test -x "$app_dir/.venv/bin/python"
usermod -a -G www-data "$service_user"
install -o root -g root -m 0755 "$(dirname "$0")/neopanel-ops.py" /usr/local/sbin/neopanel-ops

cat > /etc/sudoers.d/neopanel-ops <<EOF
$service_user ALL=(root) NOPASSWD: /usr/local/sbin/neopanel-ops *
EOF
chmod 0440 /etc/sudoers.d/neopanel-ops
visudo -cf /etc/sudoers.d/neopanel-ops

install -d -o root -g www-data -m 0750 /var/www/neopanel
install -d -o root -g www-data -m 0750 /var/backups/neopanel

cat > /etc/systemd/system/neopanel-scheduler.service <<EOF
[Unit]
Description=NeoPanel scheduled backups
After=network.target mariadb.service

[Service]
Type=oneshot
User=$service_user
Group=$service_user
SupplementaryGroups=www-data
WorkingDirectory=$app_dir
EnvironmentFile=-/etc/neopanel/neopanel.env
ExecStart=$app_dir/.venv/bin/python -m app.scheduler
EOF

cat > /etc/systemd/system/neopanel-scheduler.timer <<'EOF'
[Unit]
Description=Run NeoPanel scheduled tasks

[Timer]
OnCalendar=*:0/5
Persistent=true
Unit=neopanel-scheduler.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now neopanel-scheduler.timer
echo "NeoPanel helper and scheduler installed. Restart the NeoPanel service to apply group membership."
