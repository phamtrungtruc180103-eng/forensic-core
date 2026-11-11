import getpass
import os
from backend.auth import create_user, _find_user
from backend.couch_store import store

def main():
    try:
        store.ensure_database()
        if _find_user("admin"):
            print("Tài khoản 'admin' đã tồn tại!")
        else:
            password = os.getenv("ADMIN_PASSWORD") or getpass.getpass("Mật khẩu admin mới (tối thiểu 12 ký tự): ")
            if len(password) < 12:
                raise ValueError("Mật khẩu admin phải có ít nhất 12 ký tự")
            create_user("admin", password, "admin", "ADMIN")
            print("Đã tạo tài khoản admin thành công!")
            print("Tên đăng nhập: admin")
            print("Mật khẩu được lấy từ ADMIN_PASSWORD hoặc dữ liệu nhập bảo mật; hệ thống không in lại mật khẩu.")
    except Exception as e:
        print(f"Lỗi: {e}")

if __name__ == "__main__":
    main()
