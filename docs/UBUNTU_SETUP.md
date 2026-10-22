# Cài đặt NeoPanel trên Ubuntu

Hướng dẫn này cài NeoPanel như một ứng dụng nội bộ phía sau Nginx. Hỗ trợ mục tiêu là Ubuntu 22.04/24.04 (Python 3.10 trở lên). Chưa có thao tác nào được thực hiện trên VPS của bạn.

## 1. Chuẩn bị máy chủ

Cài Python, Nginx, MariaDB, Certbot và các PHP-FPM phiên bản cần cung cấp. Ví dụ:

```bash
sudo apt update
sudo apt install -y python3 python3-venv nginx mariadb-server certbot python3-certbot-nginx php8.1-fpm
sudo adduser --system --group --home /opt/neopanel --no-create-home neopanel
sudo install -d -o neopanel -g neopanel -m 0750 /opt/neopanel/data
```

Chép mã nguồn vào `/opt/neopanel`, tạo môi trường Python và cài dependencies:

```bash
sudo -u neopanel python3 -m venv /opt/neopanel/.venv
sudo -u neopanel /opt/neopanel/.venv/bin/pip install -r /opt/neopanel/requirements.txt
```

Đặt file `.env` không chứa khóa bí mật ở chế độ public; chỉ admin root được đọc. Tạo khóa session độc lập:

```bash
sudo install -d -o root -g neopanel -m 0750 /etc/neopanel
sudo sh -c 'umask 027; python3 -c "import secrets; print(secrets.token_urlsafe(48))" > /opt/neopanel/data/session_secret'
sudo chown neopanel:neopanel /opt/neopanel/data/session_secret
sudo chmod 0640 /opt/neopanel/data/session_secret
```

Nếu muốn kiểm tra DNS, thêm `NEOPANEL_PUBLIC_IP=<địa-chỉ-IP-public>` vào `/etc/neopanel/neopanel.env` (quyền `0640`, owner `root:neopanel`). Đặt `NEOPANEL_COOKIE_SECURE=1` khi phục vụ HTTPS; unit systemd mẫu đã bật cờ này.

## 2. Cài helper đặc quyền

Từ thư mục mã nguồn trên VPS, chạy helper installer bằng root:

```bash
sudo ops/install-helper.sh neopanel /opt/neopanel
```

Installer cài `/usr/local/sbin/neopanel-ops` thuộc root, sudoers giới hạn user dịch vụ vào helper đó, tạo `/var/www/neopanel` và `/var/backups/neopanel`, đồng thời cài timer sao lưu. Helper nhận JSON trên stdin và chỉ chấp nhận các hành động cố định; không nhận lệnh shell do người dùng nhập.

Ứng dụng cần đọc các document root để hiển thị file và cần đọc/stream backup. User `neopanel` được thêm vào nhóm `www-data`; khởi động lại service sau khi cài helper để nạp nhóm mới.

## 3. Khởi động ứng dụng và reverse proxy

Unit mẫu dùng đường dẫn `/opt/neopanel`; cài và bật:

```bash
sudo install -o root -g root -m 0644 ops/neopanel.service /etc/systemd/system/neopanel.service
sudo systemctl daemon-reload
sudo systemctl enable --now neopanel
```

Sửa `ops/nginx-neopanel.conf` để dùng hostname thật, cài vào `sites-available`, tạo symlink trong `sites-enabled`, rồi kiểm tra và reload Nginx:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Cấu hình TLS cho hostname quản trị bằng Certbot. Website hosting được NeoPanel tạo riêng trong `/etc/nginx/sites-available/neopanel` và `/etc/nginx/sites-enabled`; cấu hình server mặc định của hệ thống không nên chiếm các domain hosting này.

Tạo admin ban đầu bằng:

```bash
cd /opt/neopanel
sudo -u neopanel .venv/bin/python -m app.init_admin
```

Lệnh yêu cầu mật khẩu tương tác tối thiểu 12 ký tự. Mở trang quản trị chỉ qua VPN, allowlist IP hoặc lớp xác thực proxy.

## 4. Module và yêu cầu vận hành

- **Website/PHP/Nginx:** mỗi website có user PHP-FPM riêng, socket Unix riêng, `open_basedir`, giới hạn pool và document root riêng. Cài PHP-FPM trước khi chọn phiên bản. Module Phiên bản PHP cho phép sửa `php.ini`, `php-fpm.conf` và file `.ini` bổ sung trong `/etc/php/<phiên-bản>/`; pool `neopanel-*.conf` vẫn do helper quản lý. Sau khi lưu, helper kiểm tra `php-fpm -t` rồi nạp lại dịch vụ. Cần cài lại helper (`sudo ops/install-helper.sh …`) sau khi cập nhật `neopanel-ops.py`.
- **Domain/DNS:** domain phụ được ghi nhận và kiểm tra bản ghi DNS; DNS chỉ được báo đúng khi có `NEOPANEL_PUBLIC_IP`. Cấu hình DNS hiện không tự thêm alias vào virtual host Nginx.
- **MariaDB:** tạo DB/user ngẫu nhiên qua socket quản trị local; mật khẩu chỉ hiển thị một lần, không lưu vào SQLite. Sao lưu DB sử dụng `mariadb-dump`.
- **SSL:** Certbot HTTP-01 cần DNS trỏ đúng và cổng 80 từ internet vào Nginx. Nginx phải dùng các site NeoPanel do helper quản lý.
- **File manager:** giới hạn dưới document root, tối đa 10 MB mỗi tệp; tải file và chỉnh sửa chỉ khả dụng cho website được phân quyền.
- **Backup:** file nằm dưới `/var/backups/neopanel`; scheduler chạy mỗi 5 phút, lịch sao lưu website hiện hỗ trợ ngày/tuần/tháng. Restore website ghi đè nội dung hiện tại. Database backup/restore là thao tác thủ công.
- **Giám sát:** số liệu CPU/RAM/đĩa/load đọc từ `/proc` và filesystem máy đang chạy NeoPanel; lưu tối đa 10.080 mẫu.
- **Phân quyền:** vai trò Super Admin, Hosting Admin, Website Manager (phân công website), Read-only. Hãy tạo ít nhất một Super Admin dự phòng trước khi khóa tài khoản quản trị chính.

## 5. Nhật ký và khắc phục

```bash
sudo systemctl status neopanel neopanel-scheduler.timer nginx mariadb
sudo journalctl -u neopanel -n 100 --no-pager
sudo journalctl -u neopanel-scheduler.service -n 100 --no-pager
sudo visudo -cf /etc/sudoers.d/neopanel-ops
```

Nếu helper báo không khả dụng, kiểm tra user dịch vụ, sudoers, nhóm `www-data`, quyền executable và helper root-owned. Không chạy Uvicorn bằng root. Sao lưu SQLite (`data/neopanel.db`) cùng khóa `session_secret` một cách bảo mật; mất khóa này sẽ đăng xuất các phiên hiện hành.
