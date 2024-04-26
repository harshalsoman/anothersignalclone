"""
curve.py: This file contains the implementations of Curve25519, Ed25519 as well as XEd25519
"""

import os, hashlib


class Curve25519:
    """
    Implementation of the Curve25519: implementation as per RFC7748
    """

    def __init__(self):
        self.mod_p = 255
        self.p = 2 ** 255 - 19
        self.base_u = 9
        self.q = 2 ** 252 + 27742317777372353535851937790883648493
        self.d = 37095705934669439343138083508754565189542113879843219016388785533085940283555
        self.a24 = 121665
        self.key_len = 32
        self.base = bytes.fromhex('0900000000000000000000000000000000000000000000000000000000000000')

    def generate_private_key(self):
        return os.urandom(self.key_len)

    def _decode_little_endian(self, b):
        return sum([b[i] << 8 * i for i in range((self.mod_p + 7) // 8)])

    def _decode_u_coordinate(self, u):
        u_list = [b for b in u]
        if self.mod_p % 8:
            u_list[-1] &= (1 << (self.mod_p % 8)) - 1
        return self._decode_little_endian(u_list)

    def _encode_u_coordinate(self, u):
        return bytearray([(u >> 8 * i) & 0xff for i in range((self.mod_p + 7) // 8)])

    def _conditional_swap(self, swap, x_2, x_3):
        dummy = (0 - swap) & (x_2 ^ x_3)
        x_2 = x_2 ^ dummy
        x_3 = x_3 ^ dummy
        return x_2, x_3

    def _scalar_multiplication(self, k, u):
        x_1 = u
        x_2 = 1
        z_2 = 0
        x_3 = u
        z_3 = 1
        swap = 0

        for t in range(self.mod_p - 1, -1, -1):
            k_t = (k >> t) & 1
            swap ^= k_t
            (x_2, x_3) = self._conditional_swap(swap, x_2, x_3)
            (z_2, z_3) = self._conditional_swap(swap, z_2, z_3)
            swap = k_t

            A = (x_2 + z_2) % self.p
            AA = (A ** 2) % self.p
            B = (x_2 - z_2) % self.p
            BB = (B ** 2) % self.p
            E = (AA - BB) % self.p
            C = (x_3 + z_3) % self.p
            D = (x_3 - z_3) % self.p
            DA = (D * A) % self.p
            CB = (C * B) % self.p
            x_3 = (((DA + CB) % self.p) ** 2) % self.p
            z_3 = (x_1 * (((DA - CB) % self.p) ** 2) % self.p) % self.p
            x_2 = (AA * BB) % self.p
            z_2 = (E * (AA + (self.a24 * E) % self.p) % self.p) % self.p

        x_2, x_3 = self._conditional_swap(swap, x_2, x_3)
        z_2, z_3 = self._conditional_swap(swap, z_2, z_3)
        res = (x_2 * (pow(z_2, self.p - 2, self.p))) % self.p
        return res

    def _decode_scalar_x25519(self, k):
        k_list = [b for b in k]
        k_list[0] &= 248
        k_list[31] &= 127
        k_list[31] |= 64
        return self._decode_little_endian(k_list)

    def x25519(self, k, u):
        k = self._decode_scalar_x25519(k)
        u = self._decode_u_coordinate(u)
        res = self._scalar_multiplication(k, u)
        return self._encode_u_coordinate(int(res))

    def get_public_key(self, private_key):
        return self.x25519(private_key, self.base)

    def encode(self, public_key):
        return b'\x01' + public_key

    def decode(self, encoded_public_key):
        return encoded_public_key[1:]

    def diffie_hellman(self, private_key, public_key):
        return self.x25519(private_key, public_key)


class Ed25519(Curve25519):
    """
    Implementation of Ed25519 curve as per RFC8032
    """

    def __init__(self):
        super().__init__()
        self.modp_sqrt_m1 = pow(2, (self.p - 1) // 4, self.p)
        G_x = 15112221349535400772501151409588531511454012693041857206046113283949847762202
        G_y = 46316835694926478169428394003475163141307993866256225615783033603165251855960
        self.G = (G_x, G_y, 1, G_x * G_y % self.p)

    def modp_inv(self, x):
        return pow(x, self.p - 2, self.p)

    def sha512_modq(self, s):
        return int.from_bytes(hashlib.sha512(s).digest(), "little") % self.q

    def point_add(self, P, Q):
        A, B = (P[1] - P[0]) * (Q[1] - Q[0]) % self.p, (P[1] + P[0]) * (Q[1] + Q[0]) % self.p
        C, D = 2 * P[3] * Q[3] * self.d % self.p, 2 * P[2] * Q[2] % self.p
        E, F, G, H = B - A, D - C, D + C, B + A
        return E * F % self.p, G * H % self.p, F * G % self.p, E * H % self.p

    # Computes Q = s * Q
    def point_mul(self, s, P):
        Q = (0, 1, 1, 0)  # Neutral element
        while s > 0:
            if s & 1:
                Q = self.point_add(Q, P)
            P = self.point_add(P, P)
            s >>= 1
        return Q

    def recover_x(self, y, sign):
        if y >= self.p:
            return None
        x2 = (y * y - 1) * self.modp_inv(self.d * y * y + 1)
        if x2 == 0:
            if sign:
                return None
            else:
                return 0

        # Compute square root of x2
        x = pow(x2, (self.p + 3) // 8, self.p)
        if (x * x - x2) % self.p != 0:
            x = x * self.modp_sqrt_m1 % self.p
        if (x * x - x2) % self.p != 0:
            return None

        if (x & 1) != sign:
            x = self.p - x
        return x

    def on_curve(self, P):
        x2, y2, z2 = (P[0] * P[0]) % self.p, (P[1] * P[1]) % self.p, (P[2] * P[2]) % self.p
        lhs, rhs = ((y2 - x2) * z2) % self.p, (z2 * z2 + self.d * x2 * y2) % self.p
        return lhs == rhs and ((P[3] * P[2]) % self.p == (P[0] * P[1]) % self.p)

    def point_compress(self, P):
        zinv = self.modp_inv(P[2])
        x = P[0] * zinv % self.p
        y = P[1] * zinv % self.p
        return int.to_bytes(y | ((x & 1) << self.mod_p), self.key_len, "little")

    def point_decompress(self, s):
        if len(s) != self.key_len:
            raise Exception("Invalid input length for decompression")
        y = int.from_bytes(s, "little")
        sign = y >> self.mod_p
        y &= (1 << self.mod_p) - 1

        x = self.recover_x(y, sign)
        if x is None:
            return None
        else:
            return (x, y, 1, x * y % self.p)

    def secret_expand(self, secret):
        if len(secret) != 32:
            raise Exception("Bad size of private key")
        h = hashlib.sha512(secret).digest()
        a = int.from_bytes(h[:32], "little")
        a &= (1 << 254) - 8
        a |= (1 << 254)
        return (a, h[32:])

    def secret_to_public(self, secret):
        (a, dummy) = self.secret_expand(secret)
        return self.point_compress(self.point_mul(a, self.G))

    def sign(self, secret, msg):
        a, prefix = self.secret_expand(secret)
        A = self.point_compress(self.point_mul(a, self.G))
        r = self.sha512_modq(prefix + msg)
        R = self.point_mul(r, self.G)
        Rs = self.point_compress(R)
        h = self.sha512_modq(Rs + A + msg)
        s = (r + h * a) % self.q
        return Rs + int.to_bytes(s, 32, "little")

    def verify(self, public, msg, signature):
        if len(public) != 32:
            raise Exception("Bad public key length")
        if len(signature) != 64:
            Exception("Bad signature length")
        A = self.point_decompress(public)
        if not A:
            return False
        Rs = signature[:32]
        R = self.point_decompress(Rs)
        if not R:
            return False
        s = int.from_bytes(signature[32:], "little")
        if s >= self.q: return False
        h = self.sha512_modq(Rs + public + msg)
        sB = self.point_mul(s, self.G)
        hA = self.point_mul(h, A)
        return self.point_equal(sB, self.point_add(R, hA))

    def point_equal(self, P, Q):
        # x1 / z1 == x2 / z2  <==>  x1 * z2 == x2 * z1
        if (P[0] * Q[2] - Q[0] * P[2]) % self.p != 0:
            return False
        if (P[1] * Q[2] - Q[1] * P[2]) % self.p != 0:
            return False
        return True


class XEd25519(Ed25519):
    """
    The XEd25519 implementation for signing and verification as per the Signal documentation
    """

    def __init__(self):
        super().__init__()

    def u_to_y(self, u):
        return ((u - 1) * self.modp_inv(u + 1)) % self.p

    def convert_mont(self, u):
        u_masked = u % pow(2, self.mod_p)
        y = self.u_to_y(u_masked)
        return y

    def calculate_key_pair(self, k):
        P = self.point_mul(k, self.G)

        zinv = self.modp_inv(P[2])
        x = P[0] * zinv % self.p
        y = P[1] * zinv % self.p
        sign = ((x & 1) << 255)

        if sign != 0:
            a = -k % self.q
            x = self.recover_x(y % self.p, 0)
            A = self.point_compress((x, y, 1, x * y % self.p))
        else:
            a = k % self.q
            A = self.point_compress(P)

        return A, a

    def hash(self, i, X):
        return hashlib.sha512(int.to_bytes(pow(2, 256) - 1 - i, self.key_len, "little") + X).digest()

    def sign(self, k, M):
        Z = os.urandom(64)
        A, a = self.calculate_key_pair(self._decode_scalar_x25519(k))
        r = int.from_bytes(self.hash(1, int.to_bytes(a, self.key_len, "little") + M + Z), "little") % self.q
        R = self.point_compress(self.point_mul(r, self.G))
        h = int.from_bytes(self.hash(0, R + A + M), "little") % self.q
        s = (r + h * a) % self.q
        return R + int.to_bytes(s, self.key_len, "little")

    def verify(self, k, M, S):
        u = self._decode_u_coordinate(k)
        R = S[:self.key_len]
        y = self.point_decompress(R)[1]
        s = int.from_bytes(S[self.key_len:], "little")
        if u >= self.p or y >= pow(2, 255) or s >= pow(2, 253):
            return False

        y = self.convert_mont(u)
        x = self.recover_x(y, 0)
        A = (x, y, 1, x * y % self.p)

        if not self.on_curve(A):
            return False

        h = int.from_bytes(self.hash(0, R + self.point_compress(A) + M), "little") % self.q
        ha = self.point_mul(h, A)
        neg_ha = (-ha[0] % self.p, ha[1], ha[2], -ha[3] % self.p)

        Rcheck = self.point_compress(self.point_add(self.point_mul(s, self.G), neg_ha))
        if R == Rcheck:
            return True
        return False
