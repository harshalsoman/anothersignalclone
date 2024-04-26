from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_der_public_key, load_pem_public_key


def save_private_key(email, private_key):
    private_key_pem = x25519.X25519PrivateKey.from_private_bytes(private_key) \
        .private_bytes(encoding=serialization.Encoding.PEM,
                       format=serialization.PrivateFormat.PKCS8,
                       encryption_algorithm=serialization.BestAvailableEncryption(email.encode())
                       )
    with open('./../keys/id', 'wb') as id_key_file:
        id_key_file.write(private_key_pem)


def load_private_key(email):
    with open('./../keys/id', 'rb') as id_key_file:
        private_key_pem = id_key_file.read()

    return load_pem_private_key(private_key_pem, email.encode()).private_bytes_raw()


def encode_public_key(public_key):
    return x25519.X25519PublicKey.from_public_bytes(public_key) \
        .public_bytes(encoding=serialization.Encoding.DER,
                      format=serialization.PublicFormat.SubjectPublicKeyInfo)


def decode_public_key(public_key_der):
    return load_der_public_key(public_key_der).public_bytes_raw()


def save_public_key(user, public_key):
    public_key_pem = x25519.X25519PublicKey.from_public_bytes(public_key) \
        .public_bytes(encoding=serialization.Encoding.PEM,
                      format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open('./../keys/' + user + '.pub', 'wb') as id_key_pub_file:
        id_key_pub_file.write(public_key_pem)


def load_public_key(user):
    with open('./../keys/' + user + '.pub', 'rb') as id_key_pub_file:
        id_key_pub = id_key_pub_file.read()

    return load_pem_public_key(id_key_pub).public_bytes_raw()
