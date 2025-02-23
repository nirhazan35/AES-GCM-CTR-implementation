from threading import Thread
import socket
import sys
import os
from aes_ctr import AESCTR
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
aes_ctr = AESCTR(aes_key)

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
            ciphertext, nonce, sender = parts
            sender = sender.decode()
            plaintext = aes_ctr.decrypt(ciphertext, nonce)
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
    nonce = os.urandom(AESCTR.NONCE_LENGTH)
    ciphertext = aes_ctr.encrypt(message.encode(), nonce)
    sock.sendto(b'|$'.join([ciphertext, nonce, recipient_name.encode()]), SERVER_ADDR)
    print("You: ", end='', flush=True)

sock.close()