import hashlib

from protocols.curve import Curve25519, Curve448


class Ed25519(Curve25519):

    def __init__(self):
        super().__init__()
        self.modp_sqrt_m1 = pow(2, (self.p-1) // 4, self.p)
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
        x2 = (y*y-1) * self.modp_inv(self.d*y*y+1)
        if x2 == 0:
            if sign:
                return None
            else:
                return 0

        # Compute square root of x2
        x = pow(x2, (self.p+3) // 8, self.p)
        if (x*x - x2) % self.p != 0:
            x = x * self.modp_sqrt_m1 % self.p
        if (x*x - x2) % self.p != 0:
            return None

        if (x & 1) != sign:
            x = self.p - x
        return x

    def on_curve(self, P):
        zinv = self.modp_inv(P[2])
        x = P[0] * zinv % self.p
        y = P[1] * zinv % self.p
        lhs = y * y
        rhs = x * x * x + 486662 * x * x + x
        return lhs == rhs

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

class Ed448(Curve448):

    def do(self):
        print('Unimplemented')