import tkinter as tk
from tkinter import messagebox

class KeyInfoWindow:
    def __init__(self, root, private_key, public_key, shared_key, peer_public_key, source):
        self.window = tk.Toplevel(root)
        self.window.title("Infomation")
        self.window.geometry("1000x450")  # Giới hạn kích thước cửa sổ là 1000x400

        # Định nghĩa font chữ với kích thước lớn hơn
        font = ("Arial", 12)  # Font Arial, cỡ chữ 12

        # Hiển thị khóa riêng (Private Key)
        tk.Label(self.window, text="Khóa riêng của máy (Private Key):", font=font).grid(row=0, column=0, sticky="w")
        tk.Label(self.window, text=str(private_key), font=font, wraplength=580, anchor="w").grid(row=0, column=1, sticky="w")

        # Hiển thị khóa công khai (Public Key)
        tk.Label(self.window, text="Khóa công khai của máy (Public Key):", font=font).grid(row=1, column=0, sticky="w")
        tk.Label(self.window, text=str(public_key), font=font, wraplength=580, anchor="w").grid(row=1, column=1, sticky="w")

        # Hiển thị khóa chia sẻ (Shared Key)
        tk.Label(self.window, text="Khóa chia sẻ (Shared Key):", font=font).grid(row=2, column=0, sticky="w")
        tk.Label(self.window, text=str(shared_key), font=font, wraplength=580, anchor="w").grid(row=2, column=1, sticky="w")

        # Hiển thị khóa công khai từ đối phương (Peer Public Key)
        tk.Label(self.window, text="Khóa công khai từ đối phương (Peer Public Key):", font=font).grid(row=3, column=0, sticky="w")
        tk.Label(self.window, text=str(peer_public_key), font=font, wraplength=580, anchor="w").grid(row=3, column=1, sticky="w")

        # Thêm label để hiển thị chữ ký
        self.signature_label = tk.Label(self.window, text="Chữ ký (Signature):", font=font)
        self.signature_label.grid(row=4, column=0, sticky="w")
        self.signature_value = tk.Label(self.window, text="Chưa có chữ ký", font=font, wraplength=580, anchor="w")
        self.signature_value.grid(row=4, column=1, sticky="w")

        # Nút đóng cửa sổ
        tk.Button(self.window, text="Đóng", command=self.window.destroy, font=font).grid(row=5, column=0, columnspan=2)

    def update_signature_display(self, signature, action_type):
        # Cập nhật chữ ký mới trong cửa sổ
        self.signature_value.config(text=f"{action_type} - {signature.hex()}")
        self.window.update()

def display_key_info(root, private_key, public_key, shared_key, peer_public_key, source):
    # Ensure this function returns a valid object
    if not hasattr(root, "key_info_window"):
        key_info_window = KeyInfoWindow(root, private_key, public_key, shared_key, peer_public_key, source)
        return key_info_window
    return None