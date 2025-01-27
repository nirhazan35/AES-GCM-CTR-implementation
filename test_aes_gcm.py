import os
import unittest
from aes_gcm import AESGCM

class TestAESGCM(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(32)
        self.iv = os.urandom(16)
        self.plaintext = b"Test message for AES-GCM"
        self.associated_data = b"Test associated data"
        self.aes_gcm = AESGCM(self.key)

    def test_encrypt_decrypt(self):
        ciphertext, auth_tag = self.aes_gcm.encrypt(self.plaintext, self.associated_data, self.iv)
        decrypted_text = self.aes_gcm.decrypt(ciphertext, self.associated_data, self.iv, auth_tag)
        self.assertEqual(self.plaintext, decrypted_text)

    def test_invalid_auth_tag(self):
        ciphertext, auth_tag = self.aes_gcm.encrypt(self.plaintext, self.associated_data, self.iv)
        invalid_auth_tag = os.urandom(len(auth_tag))  # Random invalid tag
        with self.assertRaises(ValueError):
            self.aes_gcm.decrypt(ciphertext, self.associated_data, self.iv, invalid_auth_tag)

if __name__ == "__main__":
    unittest.main()
