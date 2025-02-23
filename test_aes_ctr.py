import pytest
import os
from cryptography.exceptions import InvalidTag
from aes_ctr import AESCTR

# Generate a random 256-bit key
VALID_KEY = os.urandom(32)
aes_ctr = AESCTR(VALID_KEY)

@pytest.mark.parametrize("key", [b"short_key", os.urandom(15), os.urandom(33)])
def test_invalid_key_length(key):
    """Ensure that invalid key lengths raise ValueError."""
    with pytest.raises(ValueError):
        AESCTR(key)

@pytest.mark.parametrize("nonce", [b"short_nonce", os.urandom(15), os.urandom(17)])
def test_invalid_nonce_length(nonce):
    """Ensure that the nonce must be exactly 16 bytes."""
    with pytest.raises(ValueError):
        aes_ctr.encrypt(b"test", nonce)

def test_encrypt_decrypt():
    """Verify encryption and decryption produce correct results."""
    plaintext = b"Secret Message"
    nonce = os.urandom(AESCTR.NONCE_LENGTH)
    
    ciphertext = aes_ctr.encrypt(plaintext, nonce)
    decrypted_text = aes_ctr.decrypt(ciphertext, nonce)
    
    assert decrypted_text == plaintext

def test_empty_plaintext():
    """Ensure that encrypting empty plaintext raises an error."""
    nonce = os.urandom(AESCTR.NONCE_LENGTH)
    with pytest.raises(ValueError):
        aes_ctr.encrypt(b"", nonce)

def test_tampered_ciphertext():
    """CTR mode doesn't provide authentication - demonstrate vulnerability."""
    plaintext = b"Tamper test"
    nonce = os.urandom(AESCTR.NONCE_LENGTH)
    
    ciphertext = aes_ctr.encrypt(plaintext, nonce)
    # Tamper with ciphertext
    modified_ciphertext = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])
    
    # No authentication - tampering isn't detected
    decrypted_text = aes_ctr.decrypt(modified_ciphertext, nonce)
    assert decrypted_text != plaintext  # Demonstrate silent failure