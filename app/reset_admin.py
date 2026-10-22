from getpass import getpass
from pwdlib import PasswordHash
from app.database import get_connection

hasher = PasswordHash.recommended()


def main():
    username = input("Tên đăng nhập admin: ").strip()

    if not username:
        print("Tên đăng nhập không hợp lệ.")
        return

    password = getpass("Mật khẩu mới: ")
    confirm = getpass("Nhập lại mật khẩu mới: ")

    if not password:
        print("Mật khẩu không được để trống.")
        return

    if password != confirm:
        print("Hai mật khẩu không khớp.")
        return

    with get_connection() as conn:
        user = conn.execute(
            "SELECT id FROM users WHERE username = ? AND role IN ('admin', 'super_admin')",
            (username,),
        ).fetchone()

        if not user:
            print("Không tìm thấy tài khoản admin này.")
            return

        conn.execute(
            "UPDATE users SET password_hash = ?, is_active = 1, session_version = session_version + 1 WHERE id = ?",
            (hasher.hash(password), user["id"]),
        )

    print("Đã đặt lại mật khẩu admin thành công.")


if __name__ == "__main__":
    main()
