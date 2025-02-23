import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class AESGCM:
    NONCE_LENGTH = 12
    TAG_LENGTH = 16

    def __init__(self, key):
        if len(key) not in (16, 24, 32):
            raise ValueError("Key must be 128, 192, or 256 bits (16/24/32 bytes).")
        self.key = key

    def encrypt(self, plaintext, associated_data, nonce):
        if not plaintext:
            raise ValueError("Plaintext cannot be empty.")
        if len(nonce) != self.NONCE_LENGTH:
            raise ValueError(f"Nonce must be {self.NONCE_LENGTH} bytes.")

        # Encrypt using AES-GCM
        encryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce),
            backend=default_backend()
        ).encryptor()
        encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Get AES-GCM authentication tag (16 bytes)
        auth_tag = encryptor.tag  

        print(f"[ENCRYPTED] Ciphertext: {ciphertext.hex()}")
        return ciphertext, auth_tag

    def decrypt(self, ciphertext, associated_data, nonce, auth_tag):
        if len(nonce) != self.NONCE_LENGTH:
            raise ValueError(f"Nonce must be {self.NONCE_LENGTH} bytes.")
        if len(auth_tag) != self.TAG_LENGTH:
            raise ValueError(f"Tag must be {self.TAG_LENGTH} bytes.")
        print(f"[DECRYPTED] Ciphertext before decryption: {ciphertext.hex()}")

        # Decrypt using AES-GCM
        decryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce, auth_tag),
            backend=default_backend()
        ).decryptor()
        decryptor.authenticate_additional_data(associated_data)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
