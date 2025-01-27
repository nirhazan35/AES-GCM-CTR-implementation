import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7

class AESGCM:
    def __init__(self, key):
        if len(key) not in (16, 24, 32):
            raise ValueError("Invalid key length: key must be 128, 192, or 256 bits.")
        self.key = key

    def encrypt(self, plaintext, associated_data, iv):
        if not plaintext:
            raise ValueError("Plaintext cannot be empty.")
        if not associated_data:
            raise ValueError("Associated data cannot be empty.")
        if len(iv) != 16:
            raise ValueError("IV must be 128 bits (16 bytes).")

        # Pad the plaintext to block size
        padder = PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # Encrypt the plaintext
        encryptor = Cipher(
            algorithms.AES(self.key), modes.CTR(iv), backend=default_backend()
        ).encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Generate the authentication tag
        auth_tag = self._generate_auth_tag(associated_data, iv, ciphertext)

        return ciphertext, auth_tag

    def decrypt(self, ciphertext, associated_data, iv, auth_tag):
        if not ciphertext:
            raise ValueError("Ciphertext cannot be empty.")
        if not associated_data:
            raise ValueError("Associated data cannot be empty.")
        if len(iv) != 16:
            raise ValueError("IV must be 128 bits (16 bytes).")
        if not auth_tag:
            raise ValueError("Authentication tag cannot be empty.")

        # Verify the authentication tag
        if not self._verify_auth_tag(associated_data, iv, ciphertext, auth_tag):
            raise ValueError("Invalid authentication tag!")

        # Decrypt the ciphertext
        decryptor = Cipher(
            algorithms.AES(self.key), modes.CTR(iv), backend=default_backend()
        ).decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad the plaintext
        unpadder = PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext

    def _generate_auth_tag(self, associated_data, iv, ciphertext):
        # Concatenate associated data, IV, and ciphertext for the HMAC input
        mac_input = associated_data + iv + ciphertext

        # Create HMAC using SHA-256
        hmac = HMAC(self.key, SHA256(), backend=default_backend())
        hmac.update(mac_input)
        return hmac.finalize()

    def _verify_auth_tag(self, associated_data, iv, ciphertext, auth_tag):
        try:
            mac_input = associated_data + iv + ciphertext

            # Recompute HMAC and verify
            hmac = HMAC(self.key, SHA256(), backend=default_backend())
            hmac.update(mac_input)
            hmac.verify(auth_tag)
            return True
        except Exception:
            return False

