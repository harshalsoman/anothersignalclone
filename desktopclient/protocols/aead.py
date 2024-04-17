from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def encrypt_with_auth(ad, msg, sk):
    key = _expand_key(ad[:32], sk)
    return AESGCM(key).encrypt(ad[:32], msg, ad[32:])


def decrypt_with_auth(ad, msg, sk):
    key = _expand_key(ad[:32], sk)
    return AESGCM(key).decrypt(ad[:32], msg, ad[32:])


def _expand_key(nonce, sk):
    pbkdf2 = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=nonce,
        iterations=100000
    )

    return pbkdf2.derive(sk)
