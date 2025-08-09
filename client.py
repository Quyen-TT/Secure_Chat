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

def receive():
    while True:
        try:
            encrypted_message = client.recv(1024)
            if encrypted_message:
                decrypted_message = decrypt_message(encrypted_message)
                display_message(f"Server: {decrypted_message}")
        except:
            client.close()
            break

def send(event=None):
    message = message_entry.get()
    message_entry.set("")
    if message:
        encrypted_message = encrypt_message(message)
        client.send(encrypted_message)
        display_message(f"Bạn: {message}")

def display_message(message):
    chat_area.config(state=tk.NORMAL)
    chat_area.insert(tk.END, message + "\n")
    chat_area.config(state=tk.DISABLED)
    chat_area.yview(tk.END)

def on_closing(event=None):
    client.close()
    root.quit()

def encrypt_message(message):
    nonce = os.urandom(12)
    aesgcm = AESGCM(derived_key)
    encrypted_message = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
    return nonce + encrypted_message

def decrypt_message(encrypted_message):
    nonce = encrypted_message[:12]
    aesgcm = AESGCM(derived_key)
    decrypted_message = aesgcm.decrypt(nonce, encrypted_message[12:], None)
    return decrypted_message.decode('utf-8')

# GUI
root = tk.Tk()
root.title("Chat Client")

frame = tk.Frame(root)
scrollbar = tk.Scrollbar(frame)
chat_area = scrolledtext.ScrolledText(frame, wrap=tk.WORD, yscrollcommand=scrollbar.set, state=tk.DISABLED)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
chat_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
frame.pack(fill=tk.BOTH, expand=True)

message_entry = tk.StringVar()
entry_field = tk.Entry(root, textvariable=message_entry)
entry_field.bind("<Return>", send)
entry_field.pack(fill=tk.X, padx=20, pady=10)

send_button = tk.Button(root, text="Gửi", command=send)
send_button.pack()

root.protocol("WM_DELETE_WINDOW", on_closing)

# kết nối socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 5555))

# trao đổi khóa ecdh
client_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
client_public_key = client_private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

server_public_key_pem = client.recv(1024)  # nhận public key server
server_public_key = load_pem_public_key(server_public_key_pem, backend=default_backend())
client.send(client_public_key)  # gửi public key của client

# tạo khóa chung
shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)
derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_key)

thread = threading.Thread(target=receive)
thread.start()

root.mainloop()
