from protocols.curve import Curve25519
from protocols.hkdf import hkdf25519, hkdf25519_64

class DR25519:
    curve25519 = Curve25519()

    def __init__(self, root_sk, private_key=None):
        self.root_sk = root_sk

        if private_key is None:
            self.private_key = DR25519.curve25519.generate_private_key()
        else:
            self.private_key = private_key
        self.public_key = DR25519.curve25519.get_public_key(self.private_key)

    def get_public_key(self):
        return self.public_key

    def update_ratchet(self, op_public_key):
        dh_sk = hkdf25519(Curve25519().diffie_hellman(self.private_key, op_public_key))
        ratchet_output = hkdf25519_64(self.root_sk + dh_sk)
        self.root_sk = ratchet_output[:32]
        self.chain_key = ratchet_output[32:]
        self.op_public_key = op_public_key


    def update_ratchet_message(self):
        ratchet_output = hkdf25519_64(self.root_sk + self.chain_key)
        self.chain_key = ratchet_output[:32]
        return ratchet_output[32:]

    def change_key(self):
        priv = DR25519.curve25519.generate_private_key()
        pub = DR25519.curve25519.get_public_key(priv)
        self.private_key = priv

        self.update_ratchet(self.op_public_key)
        return pub