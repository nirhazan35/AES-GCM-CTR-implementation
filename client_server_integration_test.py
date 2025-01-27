import unittest
import threading
import socket
import os
import time
from aes_gcm import AESGCM
from server import main as server_main

class TestClientServerIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Start the server in a separate thread."""
        print("Starting server")
        cls.server_thread = threading.Thread(target=server_main, daemon=True)
        cls.server_thread.start()

    def setUp(self):
        """Set up the AES key and associated data."""
        print("Setting up test")
        self.key = b'T\xf8p\xcb\xc1n\xd6\xa1}\x93\x1f\x94\x9d\xd7\xb7\xe6yT\r\xe4\xb0\x8b\x8b\xd00\x00\xdd<\xb2\xba\xe2\xf3'
        self.associated_data = b"authenticated-data"
        self.aes_gcm = AESGCM(self.key)
        self.server_address = ('127.0.0.1', 9999)

    def test_client_to_server_to_client(self):
        """Simulate two clients communicating through the server."""
        print("Running test")
        # Start two clients
        client1_thread = threading.Thread(target=self.client_behavior, args=("Client1", "Client2", "Hello from Client1"))
        client2_thread = threading.Thread(target=self.client_behavior, args=("Client2", None, None))

        client1_thread.start()
        time.sleep(1)  # Wait for the first client to send a message
        client2_thread.start()

        client1_thread.join()
        client2_thread.join()

    def client_behavior(self, client_name, recipient_name, message):
        """Simulate client sending and receiving messages."""
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_socket.sendto(client_name.encode(), self.server_address)  # Register with the server

        if message:
            # Encrypt and send the message to the server
            iv = os.urandom(16)
            plaintext = f"{recipient_name}|{message}".encode()
            ciphertext, auth_tag = self.aes_gcm.encrypt(plaintext, self.associated_data, iv)
            encrypted_message = ciphertext + b'|$' + iv + b'|$' + auth_tag
            client_socket.sendto(encrypted_message, self.server_address)
        else:
            # Wait to receive a message from the server
            data, _ = client_socket.recvfrom(2048)
            ciphertext, iv, auth_tag = data.split(b'|$')
            plaintext = self.aes_gcm.decrypt(ciphertext, self.associated_data, iv, auth_tag)
            print(f"{client_name} received: {plaintext.decode()}")

        client_socket.close()

if __name__ == "__main__":
    unittest.main()
