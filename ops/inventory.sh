#!/bin/bash
H(){ echo; echo "===== $1 ====="; }

H "HỆ ĐIỀU HÀNH"
lsb_release -ds; uname -r; uptime -p

H "WEB SERVER"
for s in nginx apache2; do
  if command -v $s >/dev/null; then
    echo "$s: đã cài | $($s -v 2>&1 | head -1) | trạng thái: $(systemctl is-active $s)"
  else echo "$s: chưa cài"; fi
done

H "NGINX - SITE ĐANG BẬT"
ls -1 /etc/nginx/sites-enabled 2>/dev/null
echo "--- server_name / root / php socket ---"
grep -hE "^\s*(listen|server_name|root|fastcgi_pass)\s" /etc/nginx/sites-enabled/* 2>/dev/null | sed 's/^\s*//'

H "APACHE - SITE ĐANG BẬT"
ls -1 /etc/apache2/sites-enabled 2>/dev/null || echo "(không có)"

H "PHP - CÁC PHIÊN BẢN ĐÃ CÀI"
for v in 7.4 8.0 8.1 8.2 8.3 8.4; do
  command -v php$v >/dev/null && echo "php$v: $(php$v -v | head -1 | cut -d' ' -f1-2) | FPM: $(systemctl is-active php$v-fpm 2>/dev/null)"
done
echo "Mặc định (lệnh php): $(php -v 2>/dev/null | head -1)"
echo "--- socket FPM ---"; ls /run/php/ 2>/dev/null

H "PHP - EXTENSION CỦA BẢN 8.3"
php8.3 -m 2>/dev/null | tr '\n' ' '; echo

H "PHP-FPM POOL"
ls -1 /etc/php/*/fpm/pool.d/ 2>/dev/null

H "DATABASE"
for s in mariadb mysql; do
  command -v $s >/dev/null && echo "$s: $($s --version 2>&1 | head -1) | trạng thái: $(systemctl is-active $s)"
done
echo "--- database và user (cần sudo) ---"
sudo mariadb -e "SHOW DATABASES; SELECT user,host FROM mysql.user;" 2>&1

H "PHPMYADMIN"
dpkg -l phpmyadmin 2>/dev/null | awk '/^ii/{print $2, $3}'

H "TÀI KHOẢN HỆ THỐNG (UID >= 1000)"
awk -F: '$3>=1000 && $3<65534 {printf "%-15s uid=%-6s home=%-22s shell=%s\n",$1,$3,$6,$7}' /etc/passwd
echo "--- tài khoản có quyền sudo ---"
getent group sudo | cut -d: -f4
echo "--- tài khoản có shell đăng nhập ---"
grep -vE "nologin|false" /etc/passwd | cut -d: -f1 | tr '\n' ' '; echo

H "TÀI KHOẢN NEOPANEL (SQLite, không hiện hash)"
sqlite3 ~/neopanel/data/neopanel.db ".tables" 2>&1

H "THƯ MỤC WEBSITE"
ls -la /var/www/ 2>/dev/null

H "CỔNG ĐANG NGHE"
ss -tlnp 2>/dev/null | awk 'NR==1 || /LISTEN/'

H "DỊCH VỤ LỖI"
systemctl --failed --no-pager --no-legend

H "TÀI NGUYÊN"
free -h | head -2; df -h / | tail -1

H "TƯỜNG LỬA"
sudo ufw status 2>&1 | head -5
