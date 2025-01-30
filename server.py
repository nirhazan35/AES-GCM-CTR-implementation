import socket
from aes_gcm import AESGCM
import os
from dotenv import load_dotenv
import binascii

load_dotenv()

# AES Configuration
aes_key_hex = os.getenv("AES_KEY")
if aes_key_hex is None:
    raise ValueError("AES_KEY is not set in the .env file")

aes_key = binascii.unhexlify(aes_key_hex)
if len(aes_key) not in (16, 24, 32):
    raise ValueError("Invalid AES key length")
aes_gcm = AESGCM(aes_key)

# Server Configuration
UDP_IP = '0.0.0.0'
UDP_PORT = 9999
ASSOCIATED_DATA = b"authenticated-data"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

# Bidirectional dictionary for client lookup
class ClientRegistry:
    def __init__(self):
        self.name_to_addr = {}
        self.addr_to_name = {}

    def register(self, name, addr):
        self.name_to_addr[name] = addr
        self.addr_to_name[addr] = name

    def get_addr(self, name):
        return self.name_to_addr.get(name)

    def get_name(self, addr):
        return self.addr_to_name.get(addr)

clients = ClientRegistry()

def main():
    print("Server started on port 9999")
    while True:
        data, addr = sock.recvfrom(4096)
        if not clients.get_name(addr):
            # New registration
            name = data.decode()
            clients.register(name, addr)
            print(f"{name} connected from {addr}")
            continue

        # Process message
        try:
            parts = data.split(b'|$')
            if len(parts) != 3:
                raise ValueError("Invalid message format")
            ciphertext, iv, auth_tag = parts
            plaintext = aes_gcm.decrypt(ciphertext, ASSOCIATED_DATA, iv, auth_tag)
            recipient, message = plaintext.decode().split("|", 1)
            sender = clients.get_name(addr)

            print(f"Routing message from {sender} to {recipient}")
            recipient_addr = clients.get_addr(recipient)
            if not recipient_addr:
                error = f"Recipient '{recipient}' not found".encode()
                iv_err = os.urandom(AESGCM.IV_LENGTH)
                ct_err, tag_err = aes_gcm.encrypt(error, ASSOCIATED_DATA, iv_err)
                sock.sendto(b'|$'.join([ct_err, iv_err, tag_err]), addr)
                continue

            # Re-encrypt with new IV for forward secrecy
            new_iv = os.urandom(AESGCM.IV_LENGTH)
            sender_msg = f"{sender}|{message}".encode()
            ct_forward, tag_forward = aes_gcm.encrypt(sender_msg, ASSOCIATED_DATA, new_iv)
            sock.sendto(b'|$'.join([ct_forward, new_iv, tag_forward]), recipient_addr)
        except Exception as e:
            print(f"Error processing message: {e}")

if __name__ == "__main__":
    main()