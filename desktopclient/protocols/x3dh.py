import hashlib
import json
import os

from protocols.aead import encrypt_with_auth, decrypt_with_auth
from protocols.curve import Curve25519
from protocols.hkdf import hkdf25519
from protocols.xeddsa import XEd25519


class X3DH25519:
    curve25519 = Curve25519()
    xed25519 = XEd25519()

    def init_x3dh(self, msg, their_id_pub, their_spk_pub_enc, their_spk_sig, their_otpk_pub):
        their_spk_pub = X3DH25519.curve25519.decode(their_spk_pub_enc)

        if not X3DH25519.xed25519.verify(their_id_pub, their_spk_pub, their_spk_sig):
            raise Exception('Invalid signature')


        my_id = X3DH25519.curve25519.generate_private_key()
        self.my_id = my_id
        my_ephemeral = X3DH25519.curve25519.generate_private_key()

        dh1 = X3DH25519.curve25519.diffie_hellman(my_id, their_spk_pub)
        dh2 = X3DH25519.curve25519.diffie_hellman(my_ephemeral, their_id_pub)
        dh3 = X3DH25519.curve25519.diffie_hellman(my_ephemeral, their_spk_pub)

        # msg['spk_id'] = int.from_bytes(hashlib.sha512(their_spk_pub).digest())

        if their_otpk_pub is None:
            sk = hkdf25519(dh1 + dh2 + dh3)
        else:
            dh4 = X3DH25519.curve25519.diffie_hellman(my_ephemeral, their_otpk_pub)
            sk = hkdf25519(dh1 + dh2 + dh3 + dh4)
            # msg['otpk_id'] = int.from_bytes(hashlib.sha512(their_otpk_pub).digest())

        ad = os.urandom(32) + X3DH25519.curve25519.encode(X3DH25519.curve25519.get_public_key(my_id)) + \
             X3DH25519.curve25519.encode(X3DH25519.curve25519.get_public_key(my_ephemeral))

        cipher = encrypt_with_auth(ad, bytes(json.dumps(msg), 'utf-8'), sk)

        return (sk, ad, cipher)

    def init_x3dh_prep(self):
        my_id = X3DH25519.curve25519.generate_private_key()
        my_spk = X3DH25519.curve25519.generate_private_key()
        my_otpk = X3DH25519.curve25519.generate_private_key()

        self.my_id = my_id
        self.my_spk = my_spk
        self.my_otpk = my_otpk

        my_id_pub = X3DH25519.curve25519.get_public_key(my_id)
        my_spk_pub = X3DH25519.curve25519.get_public_key(my_spk)
        my_otpk_pub = X3DH25519.curve25519.get_public_key(my_otpk)

        my_spk_sig = X3DH25519.xed25519.sign(my_id, my_spk_pub, b'\xff')
        my_spk_pub_enc = X3DH25519.xed25519.encode(my_spk_pub)

        return (my_id_pub, my_spk_pub_enc, my_spk_sig, my_otpk_pub)

    def x3dh(self, ad, cipher):
        their_id_pub = X3DH25519.curve25519.decode(ad[32:65])
        their_eph_pub = X3DH25519.curve25519.decode(ad[65:])
        dh1 = X3DH25519.curve25519.diffie_hellman(self.my_spk, their_id_pub)
        dh2 = X3DH25519.curve25519.diffie_hellman(self.my_id, their_eph_pub)
        dh3 = X3DH25519.curve25519.diffie_hellman(self.my_spk, their_eph_pub)

        if self.my_otpk is None:
            sk = hkdf25519(dh1 + dh2 + dh3)
        else:
            dh4 = X3DH25519.curve25519.diffie_hellman(self.my_otpk, their_eph_pub)
            sk = hkdf25519(dh1 + dh2 + dh3 + dh4)

        msg = json.loads(decrypt_with_auth(ad, cipher, sk).decode('utf-8'))

        return (sk, msg)
