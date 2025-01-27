import os
import unittest
from aes_gcm import AESGCM

class TestAESGCM(unittest.TestCase):
    def setUp(self):
        """Set up a valid key, IV, and associated data for tests."""
        self.key = os.urandom(32)  # 256-bit key
        self.iv = os.urandom(16)  # 128-bit IV
        self.associated_data = b"authenticated-data"
        self.aes_gcm = AESGCM(self.key)
        
        # Sample plaintext for testing
        self.plaintext = b"This is a secret message."

    def test_encrypt_decrypt_success(self):
        """Test successful encryption and decryption."""
        ciphertext, auth_tag = self.aes_gcm.encrypt(self.plaintext, self.associated_data, self.iv)
        decrypted = self.aes_gcm.decrypt(ciphertext, self.associated_data, self.iv, auth_tag)
        self.assertEqual(self.plaintext, decrypted)

    def test_encrypt_empty_plaintext(self):
        """Test encryption with empty plaintext raises ValueError."""
        with self.assertRaises(ValueError):
            self.aes_gcm.encrypt(b"", self.associated_data, self.iv)

    def test_encrypt_empty_associated_data(self):
        """Test encryption with empty associated data raises ValueError."""
        with self.assertRaises(ValueError):
            self.aes_gcm.encrypt(self.plaintext, b"", self.iv)

    def test_encrypt_invalid_iv_length(self):
        """Test encryption with invalid IV length raises ValueError."""
        with self.assertRaises(ValueError):
            self.aes_gcm.encrypt(self.plaintext, self.associated_data, os.urandom(8))

    def test_decrypt_with_invalid_auth_tag(self):
        """Test decryption with invalid authentication tag raises ValueError."""
        ciphertext, auth_tag = self.aes_gcm.encrypt(self.plaintext, self.associated_data, self.iv)
        invalid_auth_tag = os.urandom(len(auth_tag))
        with self.assertRaises(ValueError):
            self.aes_gcm.decrypt(ciphertext, self.associated_data, self.iv, invalid_auth_tag)

    def test_decrypt_with_modified_ciphertext(self):
        """Test decryption with modified ciphertext raises ValueError."""
        ciphertext, auth_tag = self.aes_gcm.encrypt(self.plaintext, self.associated_data, self.iv)
        modified_ciphertext = ciphertext[:-1] + b"0"  # Modify the last byte
        with self.assertRaises(ValueError):
            self.aes_gcm.decrypt(modified_ciphertext, self.associated_data, self.iv, auth_tag)

    def test_invalid_key_length(self):
        """Test initializing AESGCM with an invalid key length raises ValueError."""
        with self.assertRaises(ValueError):
            AESGCM(os.urandom(10))  # Invalid key length

    def test_invalid_AESGCM_key(self):
        """Test initializing AESGCM with an invalid key length raises ValueError."""
        ciphertext, auth_tag = self.aes_gcm.encrypt(self.plaintext, self.associated_data, self.iv)
        aes_gcm = AESGCM(os.urandom(16))
        with self.assertRaises(ValueError):
            aes_gcm.decrypt(ciphertext, self.associated_data, self.iv, auth_tag)

if __name__ == "__main__":
    unittest.main()
