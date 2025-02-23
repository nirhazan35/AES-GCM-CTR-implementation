import pytest
import os
from aes_gcm import AESGCM
from aes_ctr import AESCTR
from cryptography.exceptions import InvalidTag

@pytest.fixture(params=['GCM', 'CTR'])
def cipher_system(request):
    key = os.urandom(32)
    if request.param == 'GCM':
        return AESGCM(key), request.param
    return AESCTR(key), request.param

def test_confidentiality(cipher_system):
    """Verify both systems provide confidentiality."""
    cipher, mode = cipher_system
    plaintext = b"Secret message"
    
    if mode == 'GCM':
        nonce = os.urandom(AESGCM.NONCE_LENGTH)
        ciphertext, _ = cipher.encrypt(plaintext, b"auth", nonce)
    else:
        nonce = os.urandom(AESCTR.NONCE_LENGTH)
        ciphertext = cipher.encrypt(plaintext, nonce)
    
    assert ciphertext != plaintext

def test_integrity_verification():
    """Verify only GCM provides integrity protection."""
    key = os.urandom(32)
    gcm = AESGCM(key)
    ctr = AESCTR(key)
    
    # GCM should detect tampering
    nonce = os.urandom(AESGCM.NONCE_LENGTH)
    ciphertext, tag = gcm.encrypt(b"test", b"auth", nonce)
    with pytest.raises(InvalidTag):
        gcm.decrypt(ciphertext[:-1] + b'X', b"auth", nonce, tag)
    
    # CTR should not detect tampering
    nonce_ctr = os.urandom(AESCTR.NONCE_LENGTH)
    ctr_ciphertext = ctr.encrypt(b"test", nonce_ctr)
    tampered = ctr_ciphertext[:-1] + b'X'
    assert ctr.decrypt(tampered, nonce_ctr) != b"test"  # Silent failure