# NeoPanel

Bảng điều khiển hosting (control panel) cho Ubuntu, viết bằng FastAPI. Quản lý website, tên miền, DNS, database MariaDB, tệp, phiên bản PHP, SSL, sao lưu và giám sát máy chủ qua giao diện web.

> **Trạng thái:** đang phát triển, phù hợp để thử nghiệm. Hãy rà soát bảo mật trước khi chạy trên máy chủ production.

## Tính năng

- **Website**: mỗi website chạy bằng user hệ thống và PHP-FPM pool riêng (có `open_basedir`), cấu hình Nginx tự sinh.
- **Tên miền và DNS**: domain phụ, bí danh, bản ghi A/AAAA/CNAME/MX/TXT/NS (ghi zone BIND9 nếu máy đã cài BIND9).
- **Cơ sở dữ liệu**: tạo database và user MariaDB, tự nhập mật khẩu hoặc để panel sinh ngẫu nhiên; kèm phpMyAdmin.
- **Quản lý tệp**: duyệt, tải lên (tối đa 100 MB/tệp), sửa, nén, giải nén, di chuyển, sao chép. Tự nhận diện Laravel khi giải nén.
- **Phiên bản PHP**: gán PHP 7.4 đến 8.4 cho từng website.
- **SSL/TLS**: cấp chứng chỉ Let's Encrypt (certbot).
- **Sao lưu và phục hồi**: sao lưu website và database, lập lịch, kiểm tra checksum.
- **Giám sát**: CPU, RAM, đĩa, tải, uptime; dịch vụ, nhật ký hoạt động, hàng đợi tác vụ.
- **Người dùng và phân quyền**: Super Admin, Hosting Admin, Website Manager, Read-only.

## Yêu cầu

- Ubuntu **22.04 hoặc 24.04**, quyền `sudo`, máy sạch (chưa cài Apache/MySQL).
- Kết nối Internet (tải gói apt và PPA `ondrej/php`).
- Tối thiểu khuyến nghị: 2 GB RAM, 20 GB đĩa.

## Cài đặt (một lệnh)

```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/MT1242/neopanel.git
cd neopanel
sudo bash install.sh --port 2102 2>&1 | tee ~/install.log
```

Cuối quá trình cài, script in địa chỉ truy cập và tài khoản `admin` kèm **mật khẩu ngẫu nhiên, chỉ hiển thị một lần**. Hãy lưu lại và đổi ngay sau khi đăng nhập.

### Tùy chọn

| Tùy chọn | Mô tả | Mặc định |
|---|---|---|
| `--port N` | Cổng truy cập panel | `2102` |
| `--php "8.1 8.3"` | Các phiên bản PHP-FPM cần cài | `8.1 8.3` |
| `--no-phpmyadmin` | Không cài phpMyAdmin | cài (cổng `8081`) |

Cài một phiên bản cố định:

```bash
git clone --branch v2 https://github.com/MT1242/neopanel.git
```

### Truy cập

```
http://IP_MAY_CHU:2102        # NeoPanel
http://IP_MAY_CHU:8081        # phpMyAdmin (đăng nhập bằng user database, không dùng root)
```

Nếu nhà cung cấp VPS có tường lửa riêng, hãy mở các cổng trên.

## Cập nhật

```bash
cd ~/neopanel
git pull
sudo bash install.sh --port 2102
```

Script chạy lại an toàn: giữ nguyên `data/` (CSDL panel, khóa phiên) và không tạo lại tài khoản admin.

## Kiến trúc

```
Trình duyệt ─► Nginx (:2102) ─► uvicorn / FastAPI (127.0.0.1:8000)
                                      │  sudo -n (allowlist)
                                      ▼
                         /usr/local/sbin/neopanel-ops   (helper chạy root)
                                      │
                 Nginx · PHP-FPM · MariaDB · certbot · BIND9 (tùy chọn)
```

- Panel chạy bằng user `neopanel`, **không** có quyền root. Mọi thao tác hệ thống đi qua helper `neopanel-ops` với danh sách tác vụ cố định và kiểm tra đường dẫn chặt chẽ.
- Mã nguồn và dữ liệu panel: `/opt/neopanel` (CSDL SQLite và khóa phiên ở `/opt/neopanel/data`).
- Biến môi trường: `/etc/neopanel/neopanel.env`.
- Website: `/var/www/neopanel/<domain>`; sao lưu: `/var/backups/neopanel`.
- Cấu hình Nginx của website: `/etc/nginx/sites-available/neopanel/`.

## Triển khai một dự án Laravel

1. **Phiên bản PHP**: gán bản PHP phù hợp (Laravel 9 dùng PHP 8.1).
2. **Cơ sở dữ liệu**: tạo database, gắn với website.
3. **Quản lý tệp**: tải file `.zip` lên, giải nén. Panel tự đặt thư mục web gốc là `public/` nếu phát hiện Laravel.
4. Tạo và sửa `.env` (`DB_DATABASE`, `DB_USERNAME`, `DB_PASSWORD`, `APP_URL`). Mật khẩu có ký tự `#`, `$` hoặc khoảng trắng phải đặt trong ngoặc kép.
5. Chạy lệnh artisan bằng đúng user và PHP của site (ví dụ PHP 8.1):

```bash
cd /var/www/neopanel/ten-mien.com
sudo -u np<hash> php8.1 artisan key:generate   # chỉ khi .env chưa có APP_KEY
sudo -u np<hash> php8.1 artisan config:clear
```

User của site có dạng `np` + 12 ký tự đầu của SHA-256 tên miền. Xem bằng:

```bash
stat -c %U /var/www/neopanel/ten-mien.com
```

## Quản trị

```bash
sudo systemctl status neopanel          # trạng thái panel
sudo systemctl restart neopanel         # khởi động lại sau khi sửa code
sudo journalctl -u neopanel -f          # xem log
```

Quên mật khẩu admin: dùng `app/reset_admin.py` (chạy trong `/opt/neopanel` bằng user `neopanel` với `.venv/bin/python -m app.reset_admin`; xem mã nguồn để biết các tham số).

## Bảo mật

- Mặc định panel chạy qua **HTTP**, mật khẩu đi dạng rõ trong mạng. Trên máy chủ thật hãy bật HTTPS (certbot với tên miền riêng, sau đó đặt `NEOPANEL_COOKIE_SECURE=1` trong `/etc/neopanel/neopanel.env`) và giới hạn IP truy cập cổng panel.
- Cổng phpMyAdmin (`8081`) mở cho toàn mạng. Dùng `--no-phpmyadmin`, hoặc chặn cổng bằng tường lửa và truy cập qua SSH tunnel:
```bash
  ssh -N -L 8081:127.0.0.1:8081 user@IP_MAY_CHU
```
- Không đưa các tệp sau lên Git: `data/`, `*.db`, `session_secret`, `.env`, bản sao lưu (đã có trong `.gitignore`).
- Service systemd hiện **chưa bật** các cờ hardening (`NoNewPrivileges`, `ProtectSystem`) vì panel gọi helper bằng `sudo`. Hướng cải thiện: tách helper thành service root riêng qua Unix socket.

## Cấu trúc thư mục

```
neopanel/
├── app/            # ứng dụng FastAPI (main.py, modules.py, security.py, ...)
│   ├── templates/  # giao diện Jinja2
│   └── static/
├── ops/            # helper root, script cài phpMyAdmin/helper, mẫu cấu hình
├── docs/           # tài liệu bổ sung
├── install.sh      # trình cài đặt một lệnh
└── requirements.txt
```

## Gỡ cài đặt

Trên máy test (lệnh xóa dữ liệu thật):

```bash
sudo systemctl disable --now neopanel neopanel-scheduler.timer
sudo rm -f /etc/systemd/system/neopanel*.service /etc/systemd/system/neopanel-scheduler.timer
sudo rm -f /etc/nginx/sites-enabled/neopanel-* /etc/nginx/sites-available/neopanel-*
sudo rm -rf /etc/nginx/sites-available/neopanel /opt/neopanel /etc/neopanel
sudo rm -f /usr/local/sbin/neopanel-ops /etc/sudoers.d/neopanel-ops
sudo systemctl daemon-reload && sudo nginx -t && sudo systemctl reload nginx
```

Website (`/var/www/neopanel`), sao lưu và database được giữ lại; xóa thủ công nếu không cần.

## Giấy phép

Chưa chọn giấy phép. Thêm tệp `LICENSE` trước khi công khai.
