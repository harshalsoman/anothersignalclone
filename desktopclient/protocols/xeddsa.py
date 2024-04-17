from protocols.curve import Curve25519, Curve448
from protocols.eddsa import Ed25519, Ed448
import hashlib

class XEd25519(Ed25519):

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

    def sign(self, k, M, Z):
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
        h = int.from_bytes(self.hash(0, R + self.point_compress(A) + M), "little") % self.q
        ha = self.point_mul(h, A)
        neg_ha = (-ha[0] % self.p, ha[1], ha[2], -ha[3] % self.p)

        Rcheck = self.point_compress(self.point_add(self.point_mul(s, self.G), neg_ha))
        if R == Rcheck:
            return True
        return False


class XEd448(Ed448):

    def __init__(self):
        super().__init__()

    def sign(self):
        return 0

    def verify(self):
        return True


if __name__ == '__main__':
    xeddsa = XEd25519()
    curve25519 = Curve25519()
    x_sk = b'2\xf8j8\xaez~TR0\x90\x11\xebu\xad\xd24\xd3\xd4\x08\xac?d\xb1\xd2\x80|\xb5\x8aO1&'
    sig = xeddsa.sign(x_sk, b'Hello World!', b'ff')

    print(xeddsa.verify(curve25519.get_public_key(x_sk), b'Hello World!', sig))