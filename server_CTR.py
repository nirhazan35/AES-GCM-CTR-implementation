import socket
from aes_ctr import AESCTR
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
aes_ctr = AESCTR(aes_key)

# Server Configuration
UDP_IP = '0.0.0.0'
UDP_PORT = 9998
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
                raise ValueError(f"Invalid message format: expected 3 parts, got {len(parts)}")
            sender = clients.get_name(addr)
            ciphertext, nonce, recipient = parts
            recipient = recipient.decode()
            print(f"Received message from {sender}, forwarding to {recipient}")
            
            recipient_addr = clients.get_addr(recipient)
            if not recipient_addr:
                print(f"Recipient '{recipient}' not found")
                error = f"Recipient '{recipient}' not found".encode()
                nonce_err = os.urandom(AESCTR.NONCE_LENGTH)
                ct_err, tag_err = aes_ctr.encrypt(error, nonce_err)
                sock.sendto(b'|$'.join([ct_err, nonce_err, tag_err]), addr)
                continue

            sock.sendto(b'|$'.join([ciphertext, nonce, sender.encode()]), recipient_addr)
        except Exception as e:
            print(f"Error processing message: {e}")

if __name__ == "__main__":
    main()