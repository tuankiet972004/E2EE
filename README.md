                                                           Mô hình E2EE Chat
Ứng dụng chat mã hóa đầu-cuối sử dụng AES và ECC, hỗ trợ tạo phòng chat riêng tư, xác thực người gửi và đảm bảo tính bảo mật toàn vẹn tin nhắn.

1.  Chức năng chính
* Tạo phòng chat
Khởi tạo một server chat để gửi và nhận tin nhắn mã hóa.

* Tham gia phòng chat
Kết nối đến server bằng địa chỉ IP để trò chuyện an toàn.

* Mã hóa và giải mã
Sử dụng AES để mã hóa nội dung và ECC để ký xác thực tin nhắn.

* Chữ ký số & Xác thực
Mỗi tin nhắn được ký bằng ECC giúp xác minh người gửi và đảm bảo không bị chỉnh sửa.

* Giao diện người dùng (GUI)
Giao diện trực quan bằng Tkinter, cho phép nhập, gửi, và hiển thị tin nhắn dễ dàng.

2.  Yêu cầu Hệ thống
* Phần cứng
CPU: Intel i3 trở lên
RAM: 4GB hoặc cao hơn
* Mạng: Internet hoặc LAN
* Phần mềm
Python 3.8+
* Thư viện:
pycryptodome hoặc cryptography
tkinter
* Cài đặt thư viện thông qua file requirements.txt 
        (pip install -r requirements.txt)

3.  Cách sử dụng
* Tạo phòng chat (server)
Mở ứng dụng, chọn Khởi tạo phòng chat.
Ghi nhớ hoặc chia sẻ địa chỉ IP được hiển thị.

* Tham gia phòng chat (client)
Nhập địa chỉ IP của server.
Chọn Tham gia phòng chat để kết nối.

* Gửi & Nhận tin nhắn
Nhập nội dung vào khung soạn thảo.
Nhấn Gửi để mã hóa, ký và gửi tin nhắn.

4.  Bảo mật
- AES đảm bảo tin nhắn được mã hóa an toàn.
- ECC xác minh nguồn gốc và tính toàn vẹn của tin nhắn.
- Ngăn chặn tấn công trung gian (MITM) và giả mạo nội dung.
