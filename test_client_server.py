import unittest
import threading
import socket
import os
import time
from aes_gcm import AESGCM
from server import main as server_main
from dotenv import load_dotenv
import binascii


class TestClientServerIntegration(unittest.TestCase):
    load_dotenv()
    @classmethod
    def setUpClass(cls):
        """Start the server in a separate thread."""
        cls.server_thread = threading.Thread(target=server_main, daemon=True)
        cls.server_thread.start()
        time.sleep(1)  # Allow server to start

    def setUp(self):
        """Set up the AES key and associated data."""
        aes_key_hex = os.getenv("AES_KEY")
        if aes_key_hex is None:
            raise ValueError("AES_KEY is not set in the .env file")
        self.key = binascii.unhexlify(aes_key_hex)
        self.associated_data = b"authenticated-data"
        self.aes_gcm = AESGCM(self.key)
        self.server_address = ('127.0.0.1', 9999)

    def test_client_to_server_to_client(self):
        """Simulate two clients communicating through the server."""
        client1_thread = threading.Thread(target=self.client_behavior, args=("Client1", "Client2", "Hello from Client1"))
        client2_thread = threading.Thread(target=self.client_behavior, args=("Client2", None, None))

        client1_thread.start()
        client2_thread.start()

        client1_thread.join()
        client2_thread.join()

    def client_behavior(self, client_name, recipient_name, message):
        """Simulate client sending and receiving messages."""
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_socket.sendto(client_name.encode(), self.server_address)  # Register with the server

        if message:
            iv = os.urandom(AESGCM.IV_LENGTH)
            plaintext = f"{recipient_name}|{message}".encode()
            ciphertext, auth_tag = self.aes_gcm.encrypt(plaintext, self.associated_data, iv)
            encrypted_message = b"|$".join([ciphertext, iv, auth_tag])
            print(f"{client_name} sending encrypted message:\n{encrypted_message}\n")
            client_socket.sendto(encrypted_message, self.server_address)
        else:
            data, _ = client_socket.recvfrom(2048)
            print(f"{client_name} received encrypted message:\n{data}\n")
            ciphertext, iv, auth_tag = data.split(b'|$')
            plaintext = self.aes_gcm.decrypt(ciphertext, self.associated_data, iv, auth_tag)
            print(f"{client_name} decrypted message: {plaintext.decode()}")

        client_socket.close()

if __name__ == "__main__":
    unittest.main()
