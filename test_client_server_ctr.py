import unittest
import threading
import socket
import os
import time
from aes_ctr import AESCTR
from server_CTR import main as server_main
from dotenv import load_dotenv
import binascii

class TestCTRClientServer(unittest.TestCase):
    load_dotenv()
    
    @classmethod
    def setUpClass(cls):
        """Start the CTR server in a separate thread."""
        cls.server_thread = threading.Thread(target=server_main, daemon=True)
        cls.server_thread.start()
        time.sleep(1)

    def setUp(self):
        aes_key_hex = os.getenv("AES_KEY")
        if aes_key_hex is None:
            self.fail("AES_KEY is not set in the .env file")
        self.key = binascii.unhexlify(aes_key_hex)
        self.aes_ctr = AESCTR(self.key)
        self.server_addr = ('127.0.0.1', 9999)

    def test_basic_communication(self):
        """Test CTR communication without authentication."""
        # Setup receiver
        receiver = threading.Thread(target=self.receiver_behavior)
        receiver.start()

        # Send message
        sender_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender_sock.sendto(b"Sender", self.server_addr)  # Register sender
        
        nonce = os.urandom(AESCTR.NONCE_LENGTH)
        ciphertext = self.aes_ctr.encrypt(b"Test message", nonce)
        message = b'|$'.join([ciphertext, nonce, b"Receiver"])
        sender_sock.sendto(message, self.server_addr)
        
        receiver.join(timeout=2)
        sender_sock.close()

    def receiver_behavior(self):
        """Receiver client thread."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"Receiver", self.server_addr)  # Register receiver
        
        data, _ = sock.recvfrom(1024)
        parts = data.split(b'|$')
        self.assertEqual(len(parts), 3, "Invalid message format")
        
        ciphertext, nonce, sender = parts
        plaintext = self.aes_ctr.decrypt(ciphertext, nonce)
        self.assertEqual(plaintext, b"Test message")
        self.assertEqual(sender.decode(), "Sender")
        sock.close()

    def test_missing_recipient_handling(self):
        """Test server handling of non-existent recipient."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"TestClient", self.server_addr)  # Registration
        
        # Send to non-existent recipient
        nonce = os.urandom(AESCTR.NONCE_LENGTH)
        ciphertext = self.aes_ctr.encrypt(b"Message", nonce)
        message = b'|$'.join([ciphertext, nonce, b"GhostRecipient"])
        sock.sendto(message, self.server_addr)
        
        # Verify error response
        response, _ = sock.recvfrom(1024)
        self.assertIn(b"not found", response, "Should notify about missing recipient")
        sock.close()

if __name__ == "__main__":
    unittest.main()