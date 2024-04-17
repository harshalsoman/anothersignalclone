import json

from protocols.curve import Curve25519
from protocols.xeddsa import XEd25519
from protocols.hkdf import hkdf25519
from protocols.aead import encrypt_with_auth, decrypt_with_auth
import os

if __name__ == '__main__':
    curve = Curve25519()
    xeddsa = XEd25519()

    alice_id = curve.generate_private_key()
    alice_id_pub = curve.get_public_key(alice_id)

    bob_id = curve.generate_private_key()
    bob_id_pub = curve.get_public_key(bob_id)

    alice_epk_id = curve.generate_private_key()
    alice_epk_id_pub = curve.get_public_key(alice_epk_id)

    bob_spk_id = curve.generate_private_key()
    bob_spk_id_pub = curve.get_public_key(bob_spk_id)

    bob_otpk_id = curve.generate_private_key()
    bob_otpk_id_pub = curve.get_public_key(bob_otpk_id)

    bob_spk_sig = xeddsa.sign(bob_id, curve.encode(bob_spk_id_pub), b'\xff')

    # alice's turn

    print(xeddsa.verify(bob_id_pub, curve.encode(bob_spk_id_pub), bob_spk_sig))

    dh1 = curve.diffie_hellman(alice_id, bob_spk_id_pub)
    dh2 = curve.diffie_hellman(alice_epk_id, bob_id_pub)
    dh3 = curve.diffie_hellman(alice_epk_id, bob_spk_id_pub)
    dh4 = curve.diffie_hellman(alice_epk_id, bob_otpk_id_pub)

    sk = hkdf25519(dh1 + dh2 + dh3 + dh4)

    ad = os.urandom(32) + curve.encode(alice_id_pub) + curve.encode(alice_epk_id_pub)

    message = {'from': 'alice', 'to': 'bob', 'otp_id': '1', 'msg': 'hello'}

    cipher = encrypt_with_auth(ad, bytes(json.dumps(message), 'utf-8'), sk)

    # bob's turn
    dh1 = curve.diffie_hellman(bob_spk_id, alice_id_pub)
    dh2 = curve.diffie_hellman(bob_id, alice_epk_id_pub)
    dh3 = curve.diffie_hellman(bob_spk_id, alice_epk_id_pub)
    dh4 = curve.diffie_hellman(bob_otpk_id, alice_epk_id_pub)

    sk = hkdf25519(dh1 + dh2 + dh3 + dh4)

    print(json.loads(decrypt_with_auth(ad, cipher, sk).decode('utf-8')))
