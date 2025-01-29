import pytest
import os
from cryptography.exceptions import InvalidSignature
from aes_gcm import AESGCM

# Generate a random 256-bit key
VALID_KEY = os.urandom(32)
aes_gcm = AESGCM(VALID_KEY)

@pytest.mark.parametrize("key", [b"short_key", os.urandom(15), os.urandom(33)])
def test_invalid_key_length(key):
    """Ensure that invalid key lengths raise ValueError."""
    with pytest.raises(ValueError):
        AESGCM(key)

@pytest.mark.parametrize("iv", [b"short_iv", os.urandom(15), os.urandom(17)])
def test_invalid_iv_length(iv):
    """Ensure that IV must be exactly 16 bytes."""
    with pytest.raises(ValueError):
        aes_gcm.encrypt(b"test", b"auth", iv)

def test_encrypt_decrypt():
    """Verify encryption and decryption produce correct results."""
    plaintext = b"Secret Message"
    associated_data = b"authenticated-data"
    iv = os.urandom(AESGCM.IV_LENGTH)

    ciphertext, auth_tag = aes_gcm.encrypt(plaintext, associated_data, iv)
    decrypted_text = aes_gcm.decrypt(ciphertext, associated_data, iv, auth_tag)

    assert decrypted_text == plaintext

def test_authentication_failure():
    """Ensure authentication failure when data is tampered."""
    plaintext = b"Test Message"
    associated_data = b"auth-data"
    iv = os.urandom(AESGCM.IV_LENGTH)

    ciphertext, auth_tag = aes_gcm.encrypt(plaintext, associated_data, iv)

    # Modify the ciphertext to force authentication failure
    modified_ciphertext = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])

    with pytest.raises(InvalidSignature):
        aes_gcm.decrypt(modified_ciphertext, associated_data, iv, auth_tag)

@pytest.mark.parametrize("auth_tag", [b"short_tag", os.urandom(31), os.urandom(33)])
def test_invalid_auth_tag_length(auth_tag):
    """Ensure authentication tag must be exactly 32 bytes."""
    plaintext = b"Test Message"
    associated_data = b"auth-data"
    iv = os.urandom(AESGCM.IV_LENGTH)
    ciphertext, _ = aes_gcm.encrypt(plaintext, associated_data, iv)

    with pytest.raises(ValueError):
        aes_gcm.decrypt(ciphertext, associated_data, iv, auth_tag)

def test_empty_plaintext():
    """Ensure that encrypting empty plaintext raises an error."""
    iv = os.urandom(AESGCM.IV_LENGTH)
    with pytest.raises(ValueError):
        aes_gcm.encrypt(b"", b"auth", iv)

def test_empty_associated_data():
    """Ensure encryption and decryption work with empty associated data."""
    plaintext = b"Test Message"
    associated_data = b""
    iv = os.urandom(AESGCM.IV_LENGTH)

    ciphertext, auth_tag = aes_gcm.encrypt(plaintext, associated_data, iv)
    decrypted_text = aes_gcm.decrypt(ciphertext, associated_data, iv, auth_tag)

    assert decrypted_text == plaintext

def test_invalid_AESGCM_key():
    """Ensure that an invalid AESGCM key raises an error."""
    invalid_key = os.urandom(10)  # Invalid key length
    with pytest.raises(ValueError):
        AESGCM(invalid_key)
