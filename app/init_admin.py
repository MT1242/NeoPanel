import os
from getpass import getpass

from pwdlib import PasswordHash

from app.database import get_connection, init_db

password_hasher = PasswordHash.recommended()


def create_admin(username, password):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'super_admin')",
            (username, password_hasher.hash(password)),
        )


def main():
    init_db()

    # Chế độ tự động (install.sh): chỉ tạo khi chưa có tài khoản nào.
    env_user = os.environ.get("NEOPANEL_ADMIN_USER", "").strip()
    env_pass = os.environ.get("NEOPANEL_ADMIN_PASSWORD", "")
    if env_user and env_pass:
        with get_connection() as conn:
            if conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                print("Đã có tài khoản, bỏ qua.")
                return
        create_admin(env_user, env_pass)
        print("Đã tạo tài khoản quản trị.")
        return

    username = input("Tên đăng nhập admin: ").strip()
    if not username or len(username) > 50:
        print("Tên đăng nhập không hợp lệ.")
        return
    password = getpass("Mật khẩu: ")
    confirm = getpass("Nhập lại mật khẩu: ")
    if not password:
        print("Mật khẩu không được để trống.")
        return
    if password != confirm:
        print("Hai mật khẩu không khớp.")
        return
    try:
        create_admin(username, password)
        print("Đã tạo tài khoản quản trị thành công.")
    except Exception as exc:
        if "UNIQUE constraint failed" in str(exc):
            print("Tên đăng nhập đã tồn tại.")
        else:
            raise


if __name__ == "__main__":
    main()