import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from protocols.curve import Curve25519, XEd25519

F_25519 = b'\xff' * 32
SALT_25519 = b'\x00' * 32
INFO = 'Yet Another Signal Clone'.encode()
MK_LIMIT = 10
RND = b'\xd9j\x03\r/\xb2\x18\xa6\x0b\x96\xce\xe5.\x05]\xed[\xf3\xc8\x98\x88"\x80\'1 wg\xbd \xdbs'

curve = Curve25519()
xeddsa = XEd25519()


def __generate_dh__():
    pr = curve.generate_private_key()
    pk = curve.get_public_key(pr)
    return (pr, pk)


def __diffie_hellman__(dh_pair, dh_pub):
    (dh_pr, _) = dh_pair
    return curve.diffie_hellman(dh_pr, dh_pub)


def __hkdf__(key_material):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT_25519,
        info=INFO
    )

    return hkdf.derive(F_25519 + key_material)


def __kdf_rk__(rk, dh_out):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=SALT_25519,
        info=INFO
    )

    key = hkdf.derive(F_25519 + rk + dh_out)
    return (key[:32], key[32:])


def __kdf_ck__(ck):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=SALT_25519,
        info=INFO
    )

    key = hkdf.derive(F_25519 + RND + ck)
    return (key[:32], key[32:])

def __expand_key__(nonce, sk):
    pbkdf2 = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=nonce,
        iterations=100000
    )

    return pbkdf2.derive(sk)

def __encrypt__(mk, msg, ad):
    key = __expand_key__(ad[:32], mk)
    return AESGCM(key).encrypt(ad[:32], msg.encode(), ad[32:])

def __decrypt__(mk, cipher, ad):
    key = __expand_key__(ad[:32], mk)
    return AESGCM(key).decrypt(ad[:32], cipher, ad[32:]).decode()

def __header__(dh_pair, pn, n):
    (_, dh_pub) = dh_pair
    return dh_pub + int.to_bytes(pn, 32) + int.to_bytes(n, 32)

def __x3dh_w_key_bundle__(id_pair, msg, key_bundle):
    (id_pr, id_pk) = id_pair
    (id_pub, spk_pub, spk_sig, otpk_pub) = key_bundle

    assert xeddsa.verify(id_pub, spk_pub, spk_sig)
    (ep_pr, ep_pk) = __generate_dh__()

    dh1 = __diffie_hellman__(id_pair, spk_pub)
    dh2 = __diffie_hellman__((ep_pr, ep_pk) , id_pub)
    dh3 = __diffie_hellman__((ep_pr, ep_pk) , spk_pub)

    if otpk_pub is None:
        sk = __hkdf__(dh1 + dh2 + dh3)
    else:
        dh4 = __diffie_hellman__((ep_pr, ep_pk) , otpk_pub)
        sk = __hkdf__(dh1 + dh2 + dh3 + dh4)

    header = os.urandom(32) + id_pk + ep_pk
    cipher = __encrypt__(sk, msg, header)
    return (sk, header, cipher)

def __x3dh_w_header__(key_bundle_pair, header, cipher):
    ((id_pr, id_pk), (spk_pr, spk_pk), (otpk_pr, otpk_pk)) = key_bundle_pair

    id_pub = header[32:64]
    ep_pub = header[64:]
    dh1 = __diffie_hellman__((spk_pr, spk_pk), id_pub)
    dh2 = __diffie_hellman__((id_pr, id_pk), ep_pub)
    dh3 = __diffie_hellman__((spk_pr, spk_pk), ep_pub)

    if otpk_pr is None:
        sk = __hkdf__(dh1 + dh2 + dh3)
    else:
        dh4 = __diffie_hellman__((otpk_pr, otpk_pk), ep_pub)
        sk = __hkdf__(dh1 + dh2 + dh3 + dh4)

    msg = __decrypt__(sk, cipher, header)
    return (sk, msg)

class Ratchet:
    def __init__(self, sk, dh_key_pair=None, dh_pub_key=None):
        self.rk = sk
        self.ck_sdr = None
        if dh_key_pair is not None:
            self.dh_sdr = dh_key_pair
        else:
            self.dh_sdr = __generate_dh__()
        if dh_pub_key is not None:
            self.dh_rcv = dh_pub_key
            (self.rk, self.ck_sdr) = __kdf_rk__(sk, __diffie_hellman__(self.dh_sdr, self.dh_rcv))
        else:
            self.dh_rcv = None
        self.ck_rcv = None
        self.n_sdr = 0
        self.n_rcv = 0
        self.pn = 0
        self.mk_skipped = {}

    def encrypt(self, msg):
        self.ck_sdr, mk = __kdf_ck__(self.ck_sdr)
        header = os.urandom(32) + __header__(self.dh_sdr, self.pn, self.n_sdr)
        self.n_sdr += 1
        return header, __encrypt__(mk, msg, header)

    def decrypt(self, header, cipher):
        plaintext = self.try_skipped_mk(header, cipher)
        if plaintext is not None:
            return plaintext

        header_dh = header[32:64]
        header_pn = int.from_bytes(header[64:96])
        header_n = int.from_bytes(header[96:144])

        if header_dh != self.dh_rcv:
            self.skip_mk(header_pn)
            self.dh_ratchet(header_dh)
        self.skip_mk(header_n)
        self.ck_rcv, mk = __kdf_ck__(self.ck_rcv)
        self.n_rcv += 1
        return __decrypt__(mk, cipher, header)

    def try_skipped_mk(self, header, ciphertext):
        header_dh = header[32:64]
        header_n = header[96:144]

        if header_dh + header_n in self.mk_skipped:
            mk = self.mk_skipped[header_dh + header_n]
            del self.mk_skipped[header_dh + header_n]
            return __decrypt__(mk, ciphertext, header)
        else:
            return None

    def skip_mk(self, until):
        assert self.n_rcv + MK_LIMIT > until
        if self.ck_rcv is None:
            return

        while self.n_rcv < until:
            self.ck_rcv, mk = __kdf_ck__(self.ck_rcv)
            self.mk_skipped[self.dh_rcv + int.to_bytes(self.n_rcv, 32)] = mk
            self.n_rcv += 1

    def dh_ratchet(self, header_dh):
        self.pn = self.n_sdr
        self.n_sdr = 0
        self.n_rcv = 0
        self.dh_rcv = header_dh
        self.rk, self.ck_rcv = __kdf_rk__(self.rk, __diffie_hellman__(self.dh_sdr, self.dh_rcv))
        self.dh_sdr = __generate_dh__()
        self.rk, self.ck_sdr = __kdf_rk__(self.rk, __diffie_hellman__(self.dh_sdr, self.dh_rcv))

if __name__ == '__main__':
    (id_sk, id_pk) = __generate_dh__()

    (id2_sk, id2_pk) = __generate_dh__()
    (spk_sk, spk_pk) = __generate_dh__()
    (otpk_sk, otpk_pk) = __generate_dh__()

    spk_sig = xeddsa.sign(id2_sk, spk_pk)

    (sk, header, cipher) = __x3dh_w_key_bundle__((id_sk, id_pk), 'wants to contact you', (id2_pk, spk_pk, spk_sig, otpk_pk))
    (sk2, msg) = __x3dh_w_header__(((id2_sk, id2_pk), (spk_sk, spk_pk), (otpk_sk, otpk_pk)), header, cipher)

    assert sk == sk2
    print(msg)
    (b_sk, b_pk) = __generate_dh__()

    alice = Ratchet(sk, dh_pub_key=b_pk)
    bob = Ratchet(sk2, (b_sk, b_pk))

    header1, cipher1 = alice.encrypt('Hey Bob, how are you?')
    header2, cipher2 = alice.encrypt('I think we should meet up')
    header3, cipher3 = alice.encrypt('Maybe, its for the best')
    header4, cipher4 = alice.encrypt('That we go ahead')
    header5, cipher5 = alice.encrypt('Hey Bob, how are you?')

    print('Alice> ', bob.decrypt(header5, cipher5))
    print('Alice> ', bob.decrypt(header3, cipher3))
    print('Alice> ', bob.decrypt(header2, cipher2))
    print('Alice> ', bob.decrypt(header4, cipher4))
    print('Alice> ', bob.decrypt(header1, cipher1))

