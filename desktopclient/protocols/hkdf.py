from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

F_25519 = b'\xff' * 32
salt_25519 = b'\0' * 32
info = b'Yet Another Signal Clone'

def hkdf25519(key_material):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_25519,
        info=info
    )

    return hkdf.derive(F_25519 + key_material)