#!/usr/bin/env bash
# NeoPanel installer for Ubuntu 22.04 / 24.04.
# Usage: sudo bash install.sh [--port 2102] [--php "8.1 8.3"] [--no-phpmyadmin]

set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Chạy bằng sudo." >&2; exit 1; }

. /etc/os-release
[[ "${ID:-}" == "ubuntu" ]] || { echo "Chỉ hỗ trợ Ubuntu." >&2; exit 1; }
case "${VERSION_ID:-}" in
    22.04|24.04) ;;
    *) echo "Chỉ hỗ trợ Ubuntu 22.04 / 24.04 (hiện tại: ${VERSION_ID:-?})." >&2; exit 1 ;;
esac

PORT=2102
PHP_VERSIONS="8.1 8.3"
PHPMYADMIN=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)
            [[ $# -ge 2 ]] || { echo "Thiếu giá trị --port." >&2; exit 2; }
            PORT="$2"
            shift 2
            ;;
        --php)
            [[ $# -ge 2 ]] || { echo "Thiếu giá trị --php." >&2; exit 2; }
            PHP_VERSIONS="$2"
            shift 2
            ;;
        --no-phpmyadmin)
            PHPMYADMIN=0
            shift
            ;;
        *)
            echo "Tham số không hợp lệ: $1" >&2
            exit 2
            ;;
    esac
done

[[ "$PORT" =~ ^[0-9]{2,5}$ ]] &&
    (( PORT >= 1 && PORT <= 65535 )) ||
    { echo "Cổng không hợp lệ." >&2; exit 2; }

# Các cổng đã dùng: 80/443 (website), 8000 (uvicorn), 8081 (phpMyAdmin)
RESERVED_PORTS="80 443 8000"
[[ "$PHPMYADMIN" -eq 1 ]] && RESERVED_PORTS+=" 8081"
for p in $RESERVED_PORTS; do
    [[ "$PORT" -ne "$p" ]] || { echo "Cổng $PORT đã được dành riêng, hãy chọn cổng khác." >&2; exit 2; }
done

for v in $PHP_VERSIONS; do
    [[ "$v" =~ ^[0-9]\.[0-9]$ ]] ||
        { echo "Phiên bản PHP không hợp lệ: $v" >&2; exit 2; }
done

SRC="$(cd "$(dirname "$0")" && pwd)"
APP_DIR=/opt/neopanel
SVC_USER=neopanel

export DEBIAN_FRONTEND=noninteractive
# Tắt hỏi/in log của needrestart khi apt cài gói
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1

echo "==> Gói hệ thống"
apt-get update
apt-get install -y \
    software-properties-common ca-certificates curl \
    nginx mariadb-server python3 python3-venv python3-pip \
    certbot python3-certbot-nginx unzip zip rsync openssl

systemctl disable --now apache2 2>/dev/null || true

echo "==> PHP-FPM: $PHP_VERSIONS"
add-apt-repository -y ppa:ondrej/php
apt-get update

for v in $PHP_VERSIONS; do
    apt-get install -y \
        "php$v-fpm" "php$v-cli" "php$v-mysql" "php$v-mbstring" \
        "php$v-xml" "php$v-curl" "php$v-zip" "php$v-gd" \
        "php$v-bcmath" "php$v-intl"

    systemctl enable --now "php$v-fpm"
done

echo "==> User dịch vụ và mã nguồn"

id "$SVC_USER" &>/dev/null ||
    useradd --system --create-home --home-dir "$APP_DIR" \
        --shell /usr/sbin/nologin "$SVC_USER"

mkdir -p "$APP_DIR"

rsync -a --delete \
    --exclude '.venv' \
    --exclude 'data' \
    --exclude 'backups' \
    --exclude '__pycache__' \
    --exclude '*.bak' \
    --exclude '.git' \
    --exclude '*.zip' \
    "$SRC"/ "$APP_DIR"/

install -d -o "$SVC_USER" -g "$SVC_USER" -m 0750 "$APP_DIR/data"

echo "==> Python venv"

[[ -x "$APP_DIR/.venv/bin/python" ]] ||
    python3 -m venv "$APP_DIR/.venv"

"$APP_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/.venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

chown -R "$SVC_USER:$SVC_USER" "$APP_DIR"

echo "==> Khởi động MariaDB và Nginx"
systemctl enable --now mariadb nginx

echo "==> Bảo mật MariaDB cơ bản"
mysql --protocol=socket -uroot <<'SQL'
DELETE FROM mysql.global_priv WHERE User='';
DELETE FROM mysql.global_priv WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
SQL

echo "==> Helper root, sudoers, timer sao lưu"
bash "$APP_DIR/ops/install-helper.sh" "$SVC_USER" "$APP_DIR"

echo "==> Khóa phiên (session_secret)"

if [[ ! -s "$APP_DIR/data/session_secret" ]]; then
    ( umask 077; openssl rand -hex 32 > "$APP_DIR/data/session_secret" )
    chown "$SVC_USER:$SVC_USER" "$APP_DIR/data/session_secret"
    chmod 600 "$APP_DIR/data/session_secret"
fi

echo "==> Tài khoản admin (chỉ lần đầu)"

ADMIN_CREATED=0

# Kiểm tra bảng users thay vì chỉ kiểm tra file DB (DB có thể tồn tại nhưng chưa có user).
HAS_USER="$(python3 - "$APP_DIR/data/neopanel.db" <<'PY'
import sqlite3, sys, os
p = sys.argv[1]
if not os.path.exists(p):
    print(0); sys.exit()
try:
    c = sqlite3.connect(p)
    print(1 if c.execute("SELECT 1 FROM users LIMIT 1").fetchone() else 0)
except sqlite3.Error:
    print(0)
PY
)"

if [[ "$HAS_USER" != "1" ]]; then
    # Đọc từ terminal để vẫn chạy được khi cài kiểu: curl ... | sudo bash
    [[ -r /dev/tty ]] || { echo "Cần terminal tương tác để nhập tài khoản admin." >&2; exit 1; }
    echo
    echo "Nhập thông tin tài khoản quản trị NeoPanel"
    echo "Tên đăng nhập: 3-64 ký tự, gồm chữ, số, dấu chấm, gạch dưới, @ hoặc -."
    echo "Mật khẩu: không được để trống."
    echo

    read -r -p "Tên đăng nhập admin [admin]: " ADMIN_USER < /dev/tty
    ADMIN_USER="${ADMIN_USER:-admin}"

    if [[ ! "$ADMIN_USER" =~ ^[a-zA-Z0-9_.@-]{3,64}$ ]]; then
        echo "Tên đăng nhập không hợp lệ." >&2
        exit 1
    fi

    while true; do
        read -r -s -p "Nhập mật khẩu admin: " ADMIN_PASS < /dev/tty
        echo

        if [[ -z "$ADMIN_PASS" ]]; then
            echo "Mật khẩu không được để trống. Hãy nhập lại."
            continue
        fi

        read -r -s -p "Xác nhận mật khẩu: " ADMIN_PASS_CONFIRM < /dev/tty
        echo

        if [[ "$ADMIN_PASS" != "$ADMIN_PASS_CONFIRM" ]]; then
            echo "Mật khẩu xác nhận không khớp. Hãy nhập lại."
            unset ADMIN_PASS ADMIN_PASS_CONFIRM
            continue
        fi

        break
    done

    echo "==> Khởi tạo tài khoản admin"

    (
        cd "$APP_DIR"
        runuser -u "$SVC_USER" -- env \
            NEOPANEL_ADMIN_USER="$ADMIN_USER" \
            NEOPANEL_ADMIN_PASSWORD="$ADMIN_PASS" \
            "$APP_DIR/.venv/bin/python" -m app.init_admin
    )

    ADMIN_CREATED=1
    unset ADMIN_PASS ADMIN_PASS_CONFIRM
else
    echo "Đã có tài khoản admin, giữ nguyên."
fi

echo "==> Cấu hình dịch vụ NeoPanel"

install -d -m 0750 -o root -g "$SVC_USER" /etc/neopanel

if [[ ! -f /etc/neopanel/neopanel.env ]]; then
    printf '%s\n' 'NEOPANEL_COOKIE_SECURE=0' > /etc/neopanel/neopanel.env
    chown root:"$SVC_USER" /etc/neopanel/neopanel.env
fi
chmod 640 /etc/neopanel/neopanel.env

# IP public dùng để kiểm tra DNS domain (modules.py)
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[[ -n "$IP" ]] || IP="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
[[ -n "$IP" ]] || IP="<server-ip>"

if ! grep -q '^NEOPANEL_PUBLIC_IP=' /etc/neopanel/neopanel.env; then
    PUB_IP="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    PUB_IP="${PUB_IP:-$IP}"
    [[ "$PUB_IP" == "<server-ip>" ]] || echo "NEOPANEL_PUBLIC_IP=$PUB_IP" >> /etc/neopanel/neopanel.env
fi

cat > /etc/systemd/system/neopanel.service <<EOF
[Unit]
Description=NeoPanel hosting control panel
After=network.target mariadb.service nginx.service
Wants=mariadb.service

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
SupplementaryGroups=www-data
WorkingDirectory=$APP_DIR
EnvironmentFile=-/etc/neopanel/neopanel.env
ExecStart=$APP_DIR/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1
Restart=on-failure
RestartSec=3
UMask=0027

[Install]
WantedBy=multi-user.target
EOF

echo "==> Cấu hình Nginx cổng $PORT"

cat > /etc/nginx/sites-available/neopanel-panel <<EOF
# managed-by-neopanel-panel
server {
    listen $PORT;
    listen [::]:$PORT;
    server_name _;

    client_max_body_size 128m;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 900s;
        proxy_send_timeout 900s;
    }
}
EOF

ln -sf /etc/nginx/sites-available/neopanel-panel \
    /etc/nginx/sites-enabled/neopanel-panel

rm -f /etc/nginx/sites-enabled/default

nginx -t

echo "==> Khởi động dịch vụ"

systemctl daemon-reload
systemctl enable neopanel
# restart (không chỉ --now) để áp dụng code mới và nhóm www-data khi cài lại
systemctl restart neopanel
systemctl reload nginx

if [[ "$PHPMYADMIN" -eq 1 ]]; then
    echo "==> phpMyAdmin (cổng 8081)"
    bash "$APP_DIR/ops/install-phpmyadmin.sh" 8081
fi

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow "$PORT"/tcp

    if [[ "$PHPMYADMIN" -eq 1 ]]; then
        ufw allow 8081/tcp
    fi
fi

echo
echo "=============================================="
echo " NeoPanel đã cài xong: http://$IP:$PORT"

if [[ "$ADMIN_CREATED" -eq 1 ]]; then
    echo " Tài khoản admin đã được tạo theo thông tin bạn nhập."
    echo " Hãy lưu lại tên đăng nhập và mật khẩu của bạn."
fi

echo "=============================================="
