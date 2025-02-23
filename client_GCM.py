from threading import Thread
import socket
import sys
import os
from aes_gcm import AESGCM
from dotenv import load_dotenv
import binascii

load_dotenv()

# AES Key Configuration
aes_key_hex = os.getenv("AES_KEY")
if aes_key_hex is None:
    raise ValueError("AES_KEY is not set in the .env file")

aes_key = binascii.unhexlify(aes_key_hex)
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
            if len(parts) != 4:
                print(f"Invalid message format: expected 4 parts, got {len(parts)}")
                continue
            ciphertext, nonce, auth_tag, sender = parts
            sender = sender.decode()
            plaintext = aes_gcm.decrypt(ciphertext, ASSOCIATED_DATA, nonce, auth_tag)
            message = plaintext.decode()
            print(f"\n[Received from {sender}] {message}\nYou: ", end='', flush=True)
        except Exception as e:
            print(f"\nError: {e}\nYou: ", end='', flush=True)

Thread(target=output_recvfrom, args=(sock,), daemon=True).start()

print("You: ", end='', flush=True)
for line in sys.stdin:
    recipient_message = line.strip()
    if not recipient_message:
        continue
    recipient_name, message = recipient_message.split("|", 1)
    nonce = os.urandom(AESGCM.NONCE_LENGTH)
    ciphertext, auth_tag = aes_gcm.encrypt(message.encode(), ASSOCIATED_DATA, nonce)
    sock.sendto(b'|$'.join([ciphertext, nonce, auth_tag, recipient_name.encode()]), SERVER_ADDR)
    print("You: ", end='', flush=True)

sock.close()