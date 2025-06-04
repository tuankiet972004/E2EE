from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import socket
import threading
import tkinter as tk
from tkinter import simpledialog

from KeyInfoWindow import display_key_info

# Biến toàn cục để kiểm soát trạng thái dừng
running = True

# Tạo khóa ECC
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Mã hóa thông điệp bằng AES
def encrypt_AES(shared_key, message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = pad(message, algorithms.AES.block_size)
    cipher_text = encryptor.update(padded_message) + encryptor.finalize()
    return iv + cipher_text

# Giải mã thông điệp bằng AES
def decrypt_AES(shared_key, cipher_text):
    iv = cipher_text[:16]
    cipher_text = cipher_text[16:]
    cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(cipher_text) + decryptor.finalize()
    return unpad(padded_message, algorithms.AES.block_size)

# Chữ ký ECC
def sign_ECC(private_key, message):
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))

# Xác thực chữ ký
def verify_ECC(public_key, signature, message):
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def is_socket_connected(sock):
    try:
        return sock.getpeername() is not None
    except OSError as e:
        print(f"Socket error: {e}")
        return False

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Application")
        self.root.geometry("600x500")

        # Biến cờ để kiểm tra trạng thái kết nối
        self.connected = False

        # Các biến để lưu giá trị sau khi kết nối thành công
        self.server_socket = None
        self.client_socket = None
        self.shared_key = None
        self.private_key = None
        self.public_key = None
        self.connection_type = ""
        self.key_info_window = None

        # Nút "Khởi tạo phòng chat" và "Tham gia phòng chat"
        self.create_room_button = tk.Button(root, text="Khởi tạo phòng chat", command=self.create_room)
        self.create_room_button.pack(pady=10)

        self.join_room_button = tk.Button(root, text="Tham gia phòng chat", command=self.join_room)
        self.join_room_button.pack(pady=10)

        # Khung chat
        self.chat_frame = tk.Frame(root)
        self.chat_text = tk.Text(self.chat_frame, height=20, width=50, state=tk.DISABLED)
        self.chat_text.pack(padx=10, pady=10)

        self.message_entry = tk.Entry(self.chat_frame, width=40)
        self.message_entry.pack(side=tk.LEFT, padx=10)

        self.send_button = tk.Button(self.chat_frame, text="Gửi", command=self.send_message, state=tk.DISABLED)
        self.send_button.pack(side=tk.LEFT, padx=10)

        self.server_label = tk.Label(root, text="")

    def create_room(self):
        self.create_room_button.pack_forget()
        self.join_room_button.pack_forget()

        self.server_label.pack(pady=10)
        self.server_ip = socket.gethostbyname(socket.gethostname())
        self.server_label.config(text=f"Server IPv4: {self.server_ip}")

        # Tạo server
        threading.Thread(target=self.start_server, daemon=True).start()

    def start_server(self):
        global running
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', 8080))
        server.listen()
        print("Server started...")

        while running:
            client, addr = server.accept()
            print(f"Connection from {addr} has been established!")

            # Lưu server_socket
            self.server_socket = client
            self.connection_type = "server"

            # Tạo khóa mới cho server
            server_private_key, server_public_key = generate_keys()
            self.private_key = server_private_key
            self.public_key = server_public_key

            # Gửi public key của server đến client
            server_public_key_pem = server_public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            client.sendall(server_public_key_pem)

            # Nhận public key từ client
            client_public_key_pem = client.recv(1024)
            client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_public_key_pem)

            # In ra khóa công khai của server dưới dạng PEM thay vì đối tượng
            client_public_key_to_pem = client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            server_public_key_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            server_private_key_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()  # Nếu không muốn mã hóa khóa riêng
            )

            # Tạo khóa chia sẻ và lưu lại
            shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)
            self.shared_key = shared_key

            # Kích hoạt khung chat
            self.enable_chat()

            # Sau khi kết nối và trao đổi khóa thành công
            self.key_info_window = display_key_info(self.root, server_private_key_pem, server_public_key_pem, shared_key, client_public_key_to_pem, "server")

            # Bắt đầu luồng để nhận tin nhắn từ client
            threading.Thread(target=self.receive_message_from_client,
                             args=(client, client_public_key, shared_key, addr), daemon=True).start()

        server.close()

    def join_room(self):
        server_ip = simpledialog.askstring("Tham gia phòng chat", "Nhập địa chỉ IPv4 của server:")

        if server_ip:
            self.create_room_button.pack_forget()
            self.join_room_button.pack_forget()

            # Kết nối tới server
            threading.Thread(target=self.connect_to_server, args=(server_ip,), daemon=True).start()

    def connect_to_server(self, server_ip):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_socket.connect((server_ip, 8080))
            print("Đã kết nối tới server")
        except Exception as e:
            print(f"Kết nối thất bại: {e}")
            return

        self.client_socket = client_socket
        self.connection_type = "client"

        # Tạo khóa cho client
        client_private_key, client_public_key = generate_keys()
        self.private_key = client_private_key
        self.public_key = client_public_key

        # Gửi public key của client tới server
        client_public_key_pem = client_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        self.client_socket.sendall(client_public_key_pem)

        # Nhận public key từ server
        server_public_key_pem = self.client_socket.recv(1024)
        server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_public_key_pem)

        # In ra khóa công khai của server dưới dạng PEM thay vì đối tượng
        server_public_key_to_pem = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()  # Nếu không muốn mã hóa khóa riêng
        )
        # Tạo khóa chia sẻ và lưu lại
        shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)
        self.shared_key = shared_key

        # Kích hoạt khung chat
        self.enable_chat()

        # Cập nhật việc gọi hàm display_key_info với tham số root
        self.key_info_window = display_key_info(self.root, client_private_key_pem, client_public_key_pem, shared_key, server_public_key_to_pem, "client")

        # Bắt đầu luồng để nhận tin nhắn từ client
        threading.Thread(target=self.receive_message_from_server,
                         args=(self.client_socket, server_public_key, shared_key), daemon=True).start()

        if self.client_socket and is_socket_connected(self.client_socket):
            print(f"Client Socket Status: {self.client_socket.fileno()}")
        else:
            print("client_socket đã không còn kết nối.")

    def send_message(self):
        message = self.message_entry.get()
        if message:
            self.display_message(message, "You")
            self.message_entry.delete(0, tk.END)

            message_bytes = message.encode('utf-8')
            cipher_text = encrypt_AES(self.shared_key, message_bytes)
            signature = sign_ECC(self.private_key, message_bytes)
            print(f"Chữ ký gửi: {signature.hex()}")

            try:
                # Cập nhật cửa sổ KeyInfoWindow với chữ ký của tin nhắn gửi
                if self.key_info_window:
                    self.key_info_window.update_signature_display(signature, "Gửi")
                else:
                    print("key_info_window is not initialized yet.")

                if self.connection_type == "server" and self.server_socket:
                    if is_socket_connected(self.server_socket):
                        self.server_socket.sendall(len(cipher_text).to_bytes(4, 'big'))
                        self.server_socket.sendall(cipher_text)
                        self.server_socket.sendall(len(signature).to_bytes(4, 'big'))
                        self.server_socket.sendall(signature)
                    else:
                        print("server_socket đã không còn kết nối.")
                elif self.connection_type == "client" and self.client_socket:
                    if is_socket_connected(self.client_socket):
                        self.client_socket.sendall(len(cipher_text).to_bytes(4, 'big'))
                        self.client_socket.sendall(cipher_text)
                        self.client_socket.sendall(len(signature).to_bytes(4, 'big'))
                        self.client_socket.sendall(signature)
                    else:
                        print("client_socket đã không còn kết nối.")
                else:
                    print("Cả client_socket và server_socket đều không kết nối.")
            except Exception as e:
                print(f"Error sending message: {e}")

    def receive_message_from_client(self, client, client_public_key, shared_key, addr):
        global running
        while running:
            try:
                # Nhận độ dài của ciphertext
                length_data = client.recv(4)
                if not length_data:
                    print(f"Client {addr} has closed the connection.")
                    break
                cipher_text_length = int.from_bytes(length_data, 'big')

                # Nhận ciphertext
                cipher_text = b""
                while len(cipher_text) < cipher_text_length:
                    part = client.recv(cipher_text_length - len(cipher_text))
                    if not part:
                        print(f"Client {addr} has closed the connection.")
                        break
                    cipher_text += part

                # Nhận chữ ký
                signature_length_data = client.recv(4)
                signature_length = int.from_bytes(signature_length_data, 'big')
                signature = client.recv(signature_length)

                if not cipher_text or not signature:
                    print("Cipher text or signature is missing.")
                    break
                # Giải mã tin nhắn
                decrypted_message = decrypt_AES(shared_key, cipher_text)

                # Xác thực chữ ký bằng ECC
                if verify_ECC(client_public_key, signature, decrypted_message):
                    message = decrypted_message.decode('utf-8')
                    print(f"Received from {addr}: {message}")

                    # Hiển thị tin nhắn trên giao diện
                    self.display_message(message, "Client")

                    # Cập nhật chữ ký nhận vào cửa sổ KeyInfoWindow
                    if self.key_info_window:
                        self.key_info_window.update_signature_display(signature, "Nhận")
                    else:
                        print("key_info_window is not initialized yet.")

                else:
                    print(f"Invalid signature from {addr}!")

            except Exception as e:
                print(f"Error receiving message from {addr}: {e}")
                break

        # Đóng kết nối với client
        client.close()
        print(f"Connection from {addr} closed.")

    def receive_message_from_server(self, client, server_public_key, shared_key):
        global running
        while running:
            try:
                # Nhận độ dài ciphertext từ server (4 byte)
                response_length_data = client.recv(4)
                if not response_length_data:
                    print("Server has closed the connection.")
                    break
                response_ciphertext_length = int.from_bytes(response_length_data, 'big')

                # Nhận ciphertext từ server
                response_cipher = b""
                while len(response_cipher) < response_ciphertext_length:
                    part = client.recv(response_ciphertext_length - len(response_cipher))
                    if not part:
                        print("Server has closed the connection.")
                        break
                    response_cipher += part

                # Nhận độ dài chữ ký từ server (4 byte)
                signature_length_data = client.recv(4)
                signature_length = int.from_bytes(signature_length_data, 'big')
                signature = client.recv(signature_length)

                if not response_cipher or not signature:
                    print("Missing cipher or signature")
                    break

                # Giải mã ciphertext
                decrypted_response = decrypt_AES(shared_key, response_cipher)

                # Xác thực chữ ký bằng public key của server
                if verify_ECC(server_public_key, signature, decrypted_response):
                    message = decrypted_response.decode('utf-8')
                    print("Server response:", message)

                    # Hiển thị phản hồi từ server
                    self.display_message(message, "Server")

                    # Cập nhật chữ ký nhận vào cửa sổ KeyInfoWindow
                    if self.key_info_window:
                        self.key_info_window.update_signature_display(signature, "Nhận")
                    else:
                        print("key_info_window is not initialized yet.")
                else:
                    print("Invalid server signature!")

            except Exception as e:
                print(f"Error receiving message: {e}")
                break

        client.close()
        print("Client closed.")

    def enable_chat(self):
        # Hiển thị khung chat và cho phép gửi tin nhắn
        self.server_label.config(text=f"You joined a server chat!")
        self.chat_frame.pack(pady=10)
        self.send_button.config(state=tk.NORMAL)
        self.connected = True

    def display_message(self, message, sender):
        # Hiển thị tin nhắn trong khung chat
        self.chat_text.config(state=tk.NORMAL)
        # Thêm định dạng cho tin nhắn với người gửi
        formatted_message = f"{sender}: {message}"
        self.chat_text.insert(tk.END, formatted_message + "\n")
        self.chat_text.config(state=tk.DISABLED)
        self.chat_text.see(tk.END)

def main():
    root = tk.Tk()
    app = ChatApp(root)  # Giả sử ChatApp là lớp giao diện chính của bạn
    root.mainloop()

if __name__ == "__main__":
    main()