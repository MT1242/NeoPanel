#!/usr/bin/env bash
# Install phpMyAdmin (official release tarball) and expose it at /phpmyadmin/ on the panel port.
# Usage: sudo ops/install-phpmyadmin.sh
# Nginx snippet: /etc/nginx/neopanel-locations/phpmyadmin.conf (included by neopanel-panel).
#
# Không dùng gói apt `phpmyadmin`: nó phụ thuộc các gói php-* chung, mà với PPA ondrej
# chúng kéo theo bản PHP mới nhất (vd. 8.4) ngoài các phiên bản đã chọn.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run this installer with sudo." >&2
  exit 1
fi

PMA_VERSION="${PMA_VERSION:-5.2.3}"
PMA_DIR=/usr/share/neopanel-phpmyadmin
PMA_CFG_DIR=/etc/neopanel/phpmyadmin
PMA_TMP=/var/lib/neopanel-phpmyadmin/tmp
URL="https://files.phpmyadmin.net/phpMyAdmin/${PMA_VERSION}/phpMyAdmin-${PMA_VERSION}-all-languages.tar.gz"

# Chọn PHP-FPM: ưu tiên 8.3/8.1, rồi bản mới nhất có socket.
socket=""
for v in 8.3 8.1 8.2; do
  if [[ -S /run/php/php${v}-fpm.sock ]]; then
    socket="/run/php/php${v}-fpm.sock"
    break
  fi
done
if [[ -z $socket ]]; then
  socket="$(ls /run/php/php[0-9]*-fpm.sock 2>/dev/null | sort -V | tail -n 1 || true)"
fi
if [[ -z $socket ]]; then
  echo "No PHP-FPM socket found in /run/php. Install php-fpm first." >&2
  exit 1
fi

if [[ ! -f "$PMA_DIR/.version" || "$(cat "$PMA_DIR/.version")" != "$PMA_VERSION" ]]; then
  echo "Downloading phpMyAdmin ${PMA_VERSION}"
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  curl -fsSL --retry 3 -o "$work/pma.tar.gz" "$URL"
  curl -fsSL --retry 3 -o "$work/pma.sha256" "$URL.sha256"
  expected="$(awk '{print $1}' "$work/pma.sha256")"
  actual="$(sha256sum "$work/pma.tar.gz" | awk '{print $1}')"
  if [[ -z $expected || $expected != "$actual" ]]; then
    echo "SHA256 mismatch for phpMyAdmin tarball." >&2
    exit 1
  fi
  mkdir -p "$work/x"
  tar -xzf "$work/pma.tar.gz" -C "$work/x" --strip-components=1
  rm -rf "$work/x/setup"
  echo "$PMA_VERSION" > "$work/x/.version"
  rm -rf "$PMA_DIR.new"
  mv "$work/x" "$PMA_DIR.new"
  rm -rf "$PMA_DIR"
  mv "$PMA_DIR.new" "$PMA_DIR"
fi

install -d -o root -g www-data -m 0750 "$PMA_CFG_DIR"
install -d -o www-data -g www-data -m 0700 "$PMA_TMP"

if [[ ! -s "$PMA_CFG_DIR/blowfish_secret" ]]; then
  ( umask 077; openssl rand -hex 16 > "$PMA_CFG_DIR/blowfish_secret" )
fi
chown root:www-data "$PMA_CFG_DIR/blowfish_secret"
chmod 0640 "$PMA_CFG_DIR/blowfish_secret"
secret="$(cat "$PMA_CFG_DIR/blowfish_secret")"

cat > "$PMA_DIR/config.inc.php" <<PHP
<?php
// managed-by-neopanel
declare(strict_types=1);
\$cfg['blowfish_secret'] = '${secret}';
\$cfg['TempDir'] = '${PMA_TMP}';
\$cfg['Servers'][1]['auth_type'] = 'cookie';
\$cfg['Servers'][1]['host'] = 'localhost';
\$cfg['Servers'][1]['AllowNoPassword'] = false;
\$cfg['Servers'][1]['AllowRoot'] = false;
\$cfg['VersionCheck'] = false;
PHP

chown -R root:www-data "$PMA_DIR"
find "$PMA_DIR" -type d -exec chmod 0750 {} +
find "$PMA_DIR" -type f -exec chmod 0640 {} +

# Gỡ server block cổng riêng (8081) của các bản cũ
rm -f /etc/nginx/sites-enabled/neopanel-phpmyadmin /etc/nginx/sites-available/neopanel-phpmyadmin

install -d -m 0755 /etc/nginx/neopanel-locations
cat > /etc/nginx/neopanel-locations/phpmyadmin.conf <<CONF
# managed-by-neopanel
location = /phpmyadmin { return 301 \$scheme://\$http_host/phpmyadmin/; }
location ^~ /phpmyadmin/ {
    alias ${PMA_DIR}/;
    index index.php;
    client_max_body_size 128m;

    location ~ ^/phpmyadmin/(libraries|templates|setup|sql|vendor|config\.inc\.php) { deny all; }
    location ~ /\. { deny all; }
    location ~ \.php\$ {
        try_files \$uri =404;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$request_filename;
        fastcgi_pass unix:${socket};
        fastcgi_read_timeout 900s;
    }
}
CONF
nginx -t
systemctl reload nginx
echo "phpMyAdmin ${PMA_VERSION} is available at http://<server-ip>:<panel-port>/phpmyadmin/ (PHP socket: ${socket})"
echo "Sign in with the database user created in NeoPanel (root login is disabled)."
