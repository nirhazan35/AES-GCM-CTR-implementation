from threading import Thread
import socket
import sys
import os
from aes_gcm import AESGCM
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Retrieve and process the AES key
aes_key = b'T\xf8p\xcb\xc1n\xd6\xa1}\x93\x1f\x94\x9d\xd7\xb7\xe6yT\r\xe4\xb0\x8b\x8b\xd00\x00\xdd<\xb2\xba\xe2\xf3'
if aes_key is None:
    raise ValueError("AES_KEY not found in the environment. Add it to the .env file.")

# Ensure the key is 128, 192, or 256 bits
if len(aes_key) not in (16, 24, 32):
    raise ValueError("Invalid key length: key must be 128, 192, or 256 bits.")

# Client configuration
server_addr = ('127.0.0.1', 9999)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)

associated_data = b"authenticated-data"

# Initialize AESGCM
aes_gcm = AESGCM(aes_key)

# Enter the client's username
my_name = input('Enter your name: ')
sock.sendto(my_name.encode(), server_addr)

# Thread to listen for messages from the server
def output_recvfrom(sock):
    while True:
        data = None
        data, _ = sock.recvfrom(2048)
        if not data:
            break

        try:
            print("Received message from server")
            ciphertext, iv, auth_tag = data.split(b'|$')  # Split received data
            plaintext = aes_gcm.decrypt(ciphertext, associated_data, iv, auth_tag)
            plaintext = plaintext.decode()
            recipient_name, message = plaintext.split("|", 1)
            print(f"{recipient_name}: {message}")
        except Exception as e:
            print(f"Failed to decrypt message: {e}")

# Start the thread for receiving messages
thread = Thread(target=output_recvfrom, args=(sock,))
thread.start()

# Sending messages
for line in sys.stdin:
    recipient_and_message = line.strip()
    iv = os.urandom(16)  # Generate a random IV for each message
    ciphertext, auth_tag = aes_gcm.encrypt(recipient_and_message.encode(), associated_data, iv)

    # Send the encrypted message in the format: ciphertext|iv|auth_tag
    data = ciphertext + b'|$' + iv + b'|$' + auth_tag
    sock.sendto(data, server_addr)

sock.close()
thread.join()
