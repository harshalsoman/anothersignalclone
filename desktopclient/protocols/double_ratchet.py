import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from protocols.curve import Curve25519, XEd25519
import pickle

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

class KeyStore:
    def __init__(self):
        self.ltk = __generate_dh__()
        self.spk = __generate_dh__()
        self.otpk = [__generate_dh__() for i in range(10)]

    def get_key_bundle(self):
        (_, ltk_pk) = self.ltk
        (_, spk_pk) = self.spk
        otpks = [k[1] for k in self.otpk] if len(self.otpk) != 0 else None
        return ltk_pk, spk_pk, otpks

    def sign_spk(self):
        (ltk_sk, _) = self.ltk
        (_, spk_pk) = self.spk
        return xeddsa.sign(ltk_sk, spk_pk)

    def del_optk(self, optk_pub):
        for pair in self.otpk:
            (_, otpk_pk) = pair
            if otpk_pk == optk_pub:
                self.otpk.remove(pair)
                break

    def fetch_otpk_sk(self, optk_pub):
        for pair in self.otpk:
            (otpk_sk, otpk_pk) = pair
            if otpk_pk == optk_pub:
                return pair

    def x3dh_w_key_bundle(self, msg, key_bundle):
        (id_pub, spk_pub, spk_sig, otpk_pub) = key_bundle

        assert xeddsa.verify(id_pub, spk_pub, spk_sig)
        (ep_pr, ep_pk) = __generate_dh__()

        dh1 = __diffie_hellman__(self.ltk, spk_pub)
        dh2 = __diffie_hellman__((ep_pr, ep_pk), id_pub)
        dh3 = __diffie_hellman__((ep_pr, ep_pk), spk_pub)

        (_, id_pk) = self.ltk
        ratchet_pair = __generate_dh__()
        (_, rathet_pk) = ratchet_pair

        header = os.urandom(32) + id_pk + ep_pk + rathet_pk
        if otpk_pub is None:
            sk = __hkdf__(dh1 + dh2 + dh3)
        else:
            dh4 = __diffie_hellman__((ep_pr, ep_pk), otpk_pub)
            sk = __hkdf__(dh1 + dh2 + dh3 + dh4)
            header = header + otpk_pk

        cipher = __encrypt__(sk, msg, header)
        return (sk, header, cipher, ratchet_pair)

    def x3dh_w_header(self, header, cipher):

        id_pub = header[32:64]
        ep_pub = header[64:96]
        ratchet_pk = header[96:128]

        dh1 = __diffie_hellman__(self.spk, id_pub)
        dh2 = __diffie_hellman__(self.ltk, ep_pub)
        dh3 = __diffie_hellman__(self.spk, ep_pub)

        if len(header) > 128:
            otpk_pk = header[128:]
            (otpk_sk, _) = self.fetch_otpk_sk(otpk_pk)
            dh4 = __diffie_hellman__((otpk_sk, otpk_pk), ep_pub)
            sk = __hkdf__(dh1 + dh2 + dh3 + dh4)
            self.del_optk(otpk_pk)
        else:
            sk = __hkdf__(dh1 + dh2 + dh3)

        msg = __decrypt__(sk, cipher, header)
        return (sk, msg, ratchet_pk)


class Ratchet:
    def __init__(self, sk, dh_key_pair=None, dh_pub_key=None, ck_sdr = None, ck_rcv = None, n_sdr = 0, n_rcv = 0, pn = 0, mk_skipped=None):
        self.rk = sk
        if mk_skipped is None:
            self.mk_skipped = {}
        if dh_key_pair is not None:
            self.dh_sdr = dh_key_pair
        else:
            self.dh_sdr = __generate_dh__()
        if dh_pub_key is not None:
            self.dh_rcv = dh_pub_key
            (self.rk, self.ck_sdr) = __kdf_rk__(sk, __diffie_hellman__(self.dh_sdr, self.dh_rcv))
        else:
            self.dh_rcv = None
        if ck_sdr is not None:
            self.rk = sk
            self.ck_sdr = ck_sdr
        self.ck_rcv = ck_rcv
        self.n_sdr = n_sdr
        self.n_rcv = n_rcv
        self.pn = pn
        self.safety_number = None

    def get_safety_number(self):
        return self.safety_number

    def __derive_safety_number__(self):
        common = int.from_bytes(self.dh_sdr[1]) ^ int.from_bytes(self.dh_rcv)
        sn = int.from_bytes(hashlib.shake_256(int.to_bytes(common, 32)).digest(6))
        return "{:02X}".format(sn)

    def get_public_key(self):
        (_, dh_pub) = self.dh_sdr
        return dh_pub

    def encrypt(self, msg):
        self.ck_sdr, mk = __kdf_ck__(self.ck_sdr)
        header = os.urandom(32) + __header__(self.dh_sdr, self.pn, self.n_sdr)
        self.n_sdr += 1
        self.safety_number = self.__derive_safety_number__()
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
        self.safety_number = self.__derive_safety_number__()
        self.dh_sdr = __generate_dh__()
        self.rk, self.ck_sdr = __kdf_rk__(self.rk, __diffie_hellman__(self.dh_sdr, self.dh_rcv))

if __name__ == '__main__':
    bob = KeyStore()

    ltk_pk, spk_pk, otpks = bob.get_key_bundle()
    spk_sig = bob.sign_spk()

    alice = KeyStore()

    otpk_pk = otpks[0] if len(otpks) else None
    (sk_alice, header, cipher, ratchet_pair) = alice.x3dh_w_key_bundle('alice requesting permission to chat', (ltk_pk, spk_pk, spk_sig, otpk_pk))
    alice = Ratchet(sk_alice, ratchet_pair)
    # hd0, cip0 = alice.encrypt('Hiscramble')

    (sk_bob, msg, ratchet_pub) = bob.x3dh_w_header(header, cipher)
    print('Alice> ', msg)
    bob = Ratchet(sk_bob, dh_pub_key=ratchet_pub)

    hdr1, cph1 = bob.encrypt('bob accepted your request to chat')



    print('Bob> ', alice.decrypt(hdr1, cph1))
    hdr2, cph2 = alice.encrypt('Hey Bob, what up?')
    hdr3, cph3 = alice.encrypt("I'm in town for a while, we should meet up")
    hdr4, cph4 = alice.encrypt("Do you remember the old park, let's meet there")

    #
    print('Alice> ', bob.decrypt(hdr2, cph2))
    print('Alice> ', bob.decrypt(hdr3, cph3))
    print('Alice> ', bob.decrypt(hdr4, cph4))

    print(bob.safety_number)
    print(alice.safety_number)

