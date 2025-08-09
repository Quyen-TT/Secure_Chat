import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

clients = {}
client_keys = {}

def handle_client(client_socket, client_address):
    try:
        # trao đổi khóa ecdh
        server_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        server_public_key = server_private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        client_socket.send(server_public_key)  # gửi public key của server

        client_public_key_pem = client_socket.recv(1024)  # nhận public key của client
        client_public_key = load_pem_public_key(client_public_key_pem, backend=default_backend())

        # tạo khóa chung
        shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_key)
        
        client_keys[client_socket] = derived_key

        while True:
            encrypted_message = client_socket.recv(1024)
            if encrypted_message:
                decrypted_message = decrypt_message(encrypted_message, client_socket)
                display_message(f"{client_address}: {decrypted_message}")
                broadcast(encrypted_message, client_socket)
            else:
                break
    except Exception as e:
        display_message(f"Error with {client_address}: {e}")

def broadcast(message, connection=None):
    for client in clients:
        if client != connection:
            client.send(message)


def start_server():
    while True:
        client_socket, client_address = server.accept()
        clients[client_socket] = client_address
        display_message(f"Thiết lập kết nối tới {client_address}")
        threading.Thread(target=handle_client, args=(client_socket, client_address)).start()

def display_message(message):
    chat_area.config(state=tk.NORMAL)
    chat_area.insert(tk.END, message + "\n")
    chat_area.config(state=tk.DISABLED)
    chat_area.yview(tk.END)

def send_message(event=None):
    message = message_entry.get()
    message_entry.set("")  # Clear input field
    if message:
        display_message(f"Server: {message}")
        encrypt_message(message)

def encrypt_message(message):
    for client, key in client_keys.items():
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        encrypted_message = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
        client.send(nonce + encrypted_message)

def decrypt_message(encrypted_message, client_socket):
    nonce = encrypted_message[:12]
    aesgcm = AESGCM(client_keys[client_socket])
    decrypted_message = aesgcm.decrypt(nonce, encrypted_message[12:], None)
    return decrypted_message.decode('utf-8')

# GUI code for server
root = tk.Tk()
root.title("Server")

frame = tk.Frame(root)
scrollbar = tk.Scrollbar(frame)
chat_area = scrolledtext.ScrolledText(frame, wrap=tk.WORD, yscrollcommand=scrollbar.set, state=tk.DISABLED)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
chat_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
frame.pack(fill=tk.BOTH, expand=True)

message_entry = tk.StringVar()
entry_field = tk.Entry(root, textvariable=message_entry)
entry_field.bind("<Return>", send_message)
entry_field.pack(fill=tk.X, padx=20, pady=10)

send_button = tk.Button(root, text="Gửi", command=send_message)
send_button.pack()

# kết nối socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 5555))
server.listen(100)

display_message("Server sẵn sàng...")

thread = threading.Thread(target=start_server)
thread.start()

root.mainloop()
