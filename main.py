import os
from aes_gcm import AESGCM

def main():
    try:
        key = os.urandom(32)  # AES-256 key
        iv = os.urandom(16)   # Initialization vector
        plaintext = b"This is a secret message."
        associated_data = b"Additional authenticated data"

        aes_gcm = AESGCM(key)

        # Encryption
        ciphertext, auth_tag = aes_gcm.encrypt(plaintext, associated_data, iv)
        print("Ciphertext:", ciphertext)
        print("Auth Tag:", auth_tag)

        # Decryption
        try:
            decrypted_text = aes_gcm.decrypt(ciphertext, associated_data, iv, auth_tag)
            print("Decrypted Text:", decrypted_text)
        except ValueError as e:
            print("Decryption failed:", e)
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
