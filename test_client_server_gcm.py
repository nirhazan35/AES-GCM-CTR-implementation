import unittest
import threading
import socket
import os
import time
import binascii
from aes_gcm import AESGCM
from server_GCM import main as server_main
from dotenv import load_dotenv


class TestGCMClientServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Start the AES-GCM server in a separate thread (daemon).
        This allows the test to proceed without manually starting the server.
        """
        load_dotenv()
        cls.server_thread = threading.Thread(target=server_main, daemon=True)
        cls.server_thread.start()
        time.sleep(1)  # Give the server a moment to start up

    def setUp(self):
        """
        Prepare AES-GCM for encryption and decryption, as well as server address info.
        """
        aes_key_hex = os.getenv("AES_KEY")
        if aes_key_hex is None:
            raise ValueError("AES_KEY is not set in the .env file")
        self.key = binascii.unhexlify(aes_key_hex)
        self.aes_gcm = AESGCM(self.key)
        self.associated_data = b"authenticated-data"
        self.server_addr = ('127.0.0.1', 9999)

    def test_client_to_server_to_client(self):
        """
        Simulate one client sending a message to another client via the AES-GCM server.
        - Client1 sends "Hello from GCM Client1" to "GCMClient2".
        - GCMClient2 receives and decrypts the message.
        """
        sender_thread = threading.Thread(
            target=self.client_send,
            args=("GCMClient1", "GCMClient2", b"Hello from GCM Client1")
        )
        receiver_thread = threading.Thread(
            target=self.client_receive,
            args=("GCMClient2",)
        )

        # Start the receiver first to ensure it's ready to receive
        receiver_thread.start()
        time.sleep(0.5)  # small delay so the server sees the receiver registration
        sender_thread.start()

        receiver_thread.join()
        sender_thread.join()

    def client_send(self, sender_name, recipient_name, plaintext):
        """
        'Client' that registers with the server, encrypts a message, and sends it.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Register the sender name
        sock.sendto(sender_name.encode(), self.server_addr)
        time.sleep(1)  # Allow server time to store sender registration

        # Encrypt the message with AES-GCM
        nonce = os.urandom(AESGCM.NONCE_LENGTH)
        ciphertext, auth_tag = self.aes_gcm.encrypt(plaintext, self.associated_data, nonce)

        # The GCM server expects messages in the format: ciphertext|$nonce|$auth_tag|$recipient
        message = b'|$'.join([ciphertext, nonce, auth_tag, recipient_name.encode()])
        sock.sendto(message, self.server_addr)
        sock.close()

    def client_receive(self, receiver_name):
        """
        'Client' that registers and then blocks, waiting for a message to be received from the server.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)  # to avoid blocking indefinitely
        # Register the receiver name
        sock.sendto(receiver_name.encode(), self.server_addr)
        time.sleep(1)  # Give the server time to store this client's address

        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            sock.close()
            self.fail(f"{receiver_name} timed out waiting for a message.")

        # The server should send back: ciphertext|$nonce|$auth_tag|$sender_name
        ciphertext, nonce, auth_tag, sender_name = data.split(b'|$')

        # Decrypt
        plaintext = self.aes_gcm.decrypt(ciphertext, self.associated_data, nonce, auth_tag)
        print(f"[{receiver_name}] received from [{sender_name.decode()}]: {plaintext.decode()}")
        sock.close()


if __name__ == "__main__":
    unittest.main()
