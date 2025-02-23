import unittest
import threading
import socket
import os
import time
from aes_gcm import AESGCM
from server_GCM import main as server_main
from dotenv import load_dotenv
import binascii

class TestGCMClientServer(unittest.TestCase):
    load_dotenv()
    
    @classmethod
    def setUpClass(cls):
        """Start the GCM server in a separate thread."""
        cls.server_thread = threading.Thread(target=server_main, daemon=True)
        cls.server_thread.start()
        time.sleep(1)  # Allow server to start

    def setUp(self):
        aes_key_hex = os.getenv("AES_KEY")
        if aes_key_hex is None:
            self.fail("AES_KEY is not set in the .env file")
        self.key = binascii.unhexlify(aes_key_hex)
        self.associated_data = b"authenticated-data"
        self.aes_gcm = AESGCM(self.key)
        self.server_addr = ('127.0.0.1', 9999)

    def test_successful_communication(self):
        """Test complete GCM communication flow with authentication."""
        # Setup receiver client
        receiver = threading.Thread(target=self.receiver_behavior)
        receiver.start()

        # Send message
        sender_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender_sock.sendto(b"Sender", self.server_addr)  # Register sender
        
        nonce = os.urandom(AESGCM.NONCE_LENGTH)
        plaintext = b"Secure message"
        ciphertext, auth_tag = self.aes_gcm.encrypt(plaintext, self.associated_data, nonce)
        message = b'|$'.join([ciphertext, nonce, auth_tag, b"Receiver"])
        sender_sock.sendto(message, self.server_addr)
        
        receiver.join(timeout=2)
        sender_sock.close()

    def receiver_behavior(self):
        """Receiver client thread."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"Receiver", self.server_addr)  # Register receiver
        
        data, _ = sock.recvfrom(1024)
        parts = data.split(b'|$')
        self.assertEqual(len(parts), 4, "Invalid message format")
        
        ciphertext, nonce, auth_tag, sender = parts
        plaintext = self.aes_gcm.decrypt(ciphertext, self.associated_data, nonce, auth_tag)
        self.assertEqual(plaintext, b"Secure message")
        self.assertEqual(sender.decode(), "Sender")
        sock.close()

    def test_invalid_authentication(self):
        """Test tampered authentication tag detection."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"TestClient", self.server_addr)  # Register client
        
        # Create valid message
        nonce = os.urandom(AESGCM.NONCE_LENGTH)
        plaintext = b"Tamper test"
        ciphertext, auth_tag = self.aes_gcm.encrypt(plaintext, self.associated_data, nonce)
        
        # Tamper with authentication tag
        tampered_tag = bytes([b ^ 0xFF for b in auth_tag])
        message = b'|$'.join([ciphertext, nonce, tampered_tag, b"Recipient"])
        
        sock.sendto(message, self.server_addr)
        response, _ = sock.recvfrom(1024)
        self.assertIn(b"Error", response, "Should receive error for invalid tag")
        sock.close()

if __name__ == "__main__":
    unittest.main()