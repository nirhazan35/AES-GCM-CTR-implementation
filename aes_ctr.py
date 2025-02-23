import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class AESCTR:
    NONCE_LENGTH = 16  # 16 bytes for nonce in CTR mode

    def __init__(self, key):
        if len(key) not in (16, 24, 32):
            raise ValueError("Key must be 128, 192, or 256 bits (16, 24, or 32 bytes).")
        self.key = key

    def encrypt(self, plaintext, nonce):
        if not plaintext:
            raise ValueError("Plaintext cannot be empty.")
        if len(nonce) != self.NONCE_LENGTH:
            raise ValueError(f"Nonce must be {self.NONCE_LENGTH} bytes.")

        # Encrypt using AES-CTR
        encryptor = Cipher(
            algorithms.AES(self.key),
            modes.CTR(nonce),
            backend=default_backend()
        ).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        print(f"[ENCRYPTED USING AES-CTR] Ciphertext: {ciphertext.hex()}")
        return ciphertext

    def decrypt(self, ciphertext, nonce):
        if len(nonce) != self.NONCE_LENGTH:
            raise ValueError(f"Nonce must be {self.NONCE_LENGTH} bytes.")
        print(f"[DECRYPTED USING AES-CTR] Ciphertext before decryption: {ciphertext.hex()}")

        # Decrypt using AES-CTR (same as encryption)
        decryptor = Cipher(
            algorithms.AES(self.key),
            modes.CTR(nonce),
            backend=default_backend()
        ).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext