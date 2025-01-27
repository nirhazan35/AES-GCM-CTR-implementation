import socket
from aes_gcm import AESGCM
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Retrieve AES key and convert it to bytes
aes_key = b'T\xf8p\xcb\xc1n\xd6\xa1}\x93\x1f\x94\x9d\xd7\xb7\xe6yT\r\xe4\xb0\x8b\x8b\xd00\x00\xdd<\xb2\xba\xe2\xf3'
if aes_key is None:
    raise ValueError("AES_KEY not found in the environment. Add it to the .env file.")

# try:
#     aes_key = bytes.fromhex(aes_key)  # Convert the hex key to bytes
# except ValueError:
#     raise ValueError("AES_KEY is not a valid hexadecimal string.")

if len(aes_key) not in (16, 24, 32):
    raise ValueError("Invalid key length: key must be 128, 192, or 256 bits.")

# Initialize AESGCM
aes_gcm = AESGCM(aes_key)

# Server configuration
UDP_IP = '0.0.0.0'
UDP_PORT = 9999
client_dict = {}

# Create the server socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
associated_data = b"authenticated-data"
sock.bind((UDP_IP, UDP_PORT))

def get_key(val):
    for key, value in client_dict.items():
        if val == value:
            return key

while True:
    data, addr = sock.recvfrom(2048)
    if addr not in client_dict.values():
        # Register a new client
        client_dict[data.decode()] = addr
        print(f"{data.decode()} is connected on port {addr[1]}.")
        print("Connected users:", list(client_dict.keys()))
    else:
        try:
            print(f"Received message from {get_key(addr)}")
            
            # Validate and split data
            print("data", data)
            if data.count(b'|') != 2:
                raise ValueError("Invalid message format. Expected ciphertext|iv|auth_tag.")
            
            ciphertext, iv, auth_tag = data.split(b'|')  # Split data into components
            
            # Decrypt the incoming data
            plaintext = aes_gcm.decrypt(ciphertext, associated_data, iv, auth_tag)
            plaintext = plaintext.decode()  # Convert plaintext bytes to string
            
            # Parse the decrypted message
            if "|" in plaintext:
                recipient_name, message = plaintext.split("|", 1)

                if recipient_name in client_dict:
                    # Encrypt the message again before sending to the recipient
                    recipient_addr = client_dict[recipient_name]
                    new_iv = os.urandom(16)  # Generate a new IV for this transmission
                    encrypted_message, new_auth_tag = aes_gcm.encrypt(
                        message.encode(), associated_data, new_iv
                    )
                    sock.sendto(encrypted_message + b'|' + new_iv + b'|' + new_auth_tag, recipient_addr)
                else:
                    # Notify the sender that the recipient does not exist
                    error_message = "Recipient not found."
                    encrypted_error, error_tag = aes_gcm.encrypt(
                        error_message.encode(), associated_data, os.urandom(16)
                    )
                    sock.sendto(encrypted_error + b'|' + error_tag, addr)
            else:
                # Notify the sender of incorrect message format
                error_message = "Invalid message format. Use: recipient_name|message"
                encrypted_error, error_tag = aes_gcm.encrypt(
                    error_message.encode(), associated_data, os.urandom(16)
                )
                sock.sendto(encrypted_error + b'|' + error_tag, addr)
        except Exception as e:
            print(f"Error handling message from {addr}: {e}")
