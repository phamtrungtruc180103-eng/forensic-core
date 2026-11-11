import getpass

from backend.auth import create_user, _find_user
from backend.couch_store import store


def main():
    try:
        store.ensure_database()
        username = input("Tên đăng nhập: ").strip().lower()
        if _find_user(username):
            raise ValueError("Tài khoản đã tồn tại")
        position = input("Vị trí (INVESTIGATOR/ANALYST/SUPERVISOR/OBSERVER): ").strip().upper()
        password = getpass.getpass("Mật khẩu (tối thiểu 12 ký tự): ")
        confirmation = getpass.getpass("Nhập lại mật khẩu: ")
        if password != confirmation:
            raise ValueError("Mật khẩu nhập lại không khớp")
        create_user(username, password, "user", position)
        print(f"Đã tạo tài khoản '{username}' với vị trí {position}. Mật khẩu không được hiển thị.")
    except Exception as e:
        print(f"Lỗi: {e}")


if __name__ == "__main__":
    main()

