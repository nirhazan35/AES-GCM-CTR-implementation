import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

class AESGCM:
    IV_LENGTH = 16
    TAG_LENGTH = 32

    def __init__(self, key):
        if len(key) not in (16, 24, 32):
            raise ValueError("Key must be 128, 192, or 256 bits (16/24/32 bytes).")
        self.key = key

    def encrypt(self, plaintext, associated_data, iv):
        if not plaintext:
            raise ValueError("Plaintext cannot be empty.")
        if len(iv) != self.IV_LENGTH:
            raise ValueError(f"IV must be {self.IV_LENGTH} bytes.")
        
        # Encrypt using AES-CTR
        encryptor = Cipher(
            algorithms.AES(self.key),
            modes.CTR(iv),
            backend=default_backend()
        ).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Generate authentication tag
        auth_tag = self._generate_auth_tag(associated_data, iv, ciphertext)
        print(f"[ENCRYPTED] IV: {iv.hex()}, Ciphertext: {ciphertext.hex()}, Tag: {auth_tag.hex()[:8]}...")
        return ciphertext, auth_tag

    def decrypt(self, ciphertext, associated_data, iv, auth_tag):
        if len(iv) != self.IV_LENGTH:
            raise ValueError(f"IV must be {self.IV_LENGTH} bytes.")
        if len(auth_tag) != self.TAG_LENGTH:
            raise ValueError(f"Tag must be {self.TAG_LENGTH} bytes.")

        # Verify authentication tag
        if not self._verify_auth_tag(associated_data, iv, ciphertext, auth_tag):
            raise InvalidSignature("Authentication tag verification failed")

        # Decrypt using AES-CTR
        decryptor = Cipher(
            algorithms.AES(self.key),
            modes.CTR(iv),
            backend=default_backend()
        ).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        print(f"[DECRYPTED] IV: {iv.hex()}, Plaintext: {plaintext.decode()}")
        return plaintext

    def _generate_auth_tag(self, associated_data, iv, ciphertext):
        mac_data = b"".join([
            associated_data,
            iv,
            ciphertext
        ])
        hmac = HMAC(self.key, SHA256(), backend=default_backend())
        hmac.update(mac_data)
        return hmac.finalize()

    def _verify_auth_tag(self, associated_data, iv, ciphertext, auth_tag):
        hmac = HMAC(self.key, SHA256(), backend=default_backend())
        hmac.update(associated_data + iv + ciphertext)
        try:
            hmac.verify(auth_tag)
            return True
        except InvalidSignature:
            return False