from threading import Thread
import socket
import sys
import os
from aes_gcm import AESGCM
from dotenv import load_dotenv

load_dotenv()

# AES Key Configuration
aes_key = b'T\xf8p\xcb\xc1n\xd6\xa1}\x93\x1f\x94\x9d\xd7\xb7\xe6yT\r\xe4\xb0\x8b\x8b\xd00\x00\xdd<\xb2\xba\xe2\xf3'
if len(aes_key) not in (16, 24, 32):
    raise ValueError("Invalid AES key length")

# Network Configuration
SERVER_ADDR = ('127.0.0.1', 9999)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ASSOCIATED_DATA = b"authenticated-data"
aes_gcm = AESGCM(aes_key)

# Check if running inside pytest
if "PYTEST_RUNNING" in os.environ:
    my_name = "TestClient"
else:
    my_name = input("Enter your name: ")
sock.sendto(my_name.encode(), SERVER_ADDR)

def output_recvfrom(sock):
    while True:
        try:
            data, _ = sock.recvfrom(4096)
            if not data:
                break
            parts = data.split(b'|$')
            if len(parts) != 3:
                print(f"Invalid message format: expected 3 parts, got {len(parts)}")
                continue
            ciphertext, iv, auth_tag = parts
            plaintext = aes_gcm.decrypt(ciphertext, ASSOCIATED_DATA, iv, auth_tag)
            recipient, message = plaintext.decode().split("|", 1)
            print(f"\n[Received from {recipient}] {message}\nYou: ", end='', flush=True)
        except Exception as e:
            print(f"\nError: {e}\nYou: ", end='', flush=True)

Thread(target=output_recvfrom, args=(sock,), daemon=True).start()

print("You: ", end='', flush=True)
for line in sys.stdin:
    recipient_message = line.strip()
    if not recipient_message:
        continue
    iv = os.urandom(AESGCM.IV_LENGTH)
    ciphertext, auth_tag = aes_gcm.encrypt(recipient_message.encode(), ASSOCIATED_DATA, iv)
    sock.sendto(b'|$'.join([ciphertext, iv, auth_tag]), SERVER_ADDR)
    print("You: ", end='', flush=True)

sock.close()