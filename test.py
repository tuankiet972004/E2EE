from multiprocessing import Process
import main  # Giả sử file bạn muốn chạy là main.py

def run_main():
    main.main()  # Giả sử main() là hàm bắt đầu trong file main.py

if __name__ == "__main__":
    # Tạo hai tiến trình để chạy main() trong main.py
    p1 = Process(target=run_main)
    p2 = Process(target=run_main)

    # Khởi động cả hai tiến trình
    p1.start()
    p2.start()

    # Đợi cả hai tiến trình hoàn thành (nếu cần)
    p1.join()
    p2.join()