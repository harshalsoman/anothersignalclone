import os
import binascii


class SecureEllipticCurve:
    def __init__(self, base_u, p, q, d, mod_p, a24, key_len):
        self.mod_p = mod_p
        self.base_u = base_u
        self.p = p
        self.q = q
        self.d = d
        self.a24 = a24
        self.key_len = key_len

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

    def get_protocol(self, encoded_public_key):
        if encoded_public_key[0] == '\x01':
            return 'curve25519'
        elif encoded_public_key[0] == '\xff':
            return 'curve448'
        else:
            return 'invalid'


class Curve25519(SecureEllipticCurve):

    def __init__(self):
        mod_p = 255
        p = 2 ** 255 - 19
        base_u = 9
        q = 2 ** 252 + 27742317777372353535851937790883648493
        d = 37095705934669439343138083508754565189542113879843219016388785533085940283555
        a24 = 121665
        key_len = 32
        self.base = binascii.unhexlify(b'0900000000000000000000000000000000000000000000000000000000000000')
        super().__init__(base_u, p, q, d, mod_p, a24, key_len)

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


class Curve448(SecureEllipticCurve):

    def __init__(self):
        base_u = 5
        mod_p = 448
        p = 2 ** 448 - 2 ** 224 - 1
        q = 2 ** 446 - 13818066809895115352007386748515426880336692474882178609894547503885
        d = 611975850744529176160423220965553317543219696871016626328968936415087860042636474891785599283666020414768678979989378147065462815545017
        a24 = 39081
        key_len = 56
        self.base = self.x448_base = binascii.unhexlify(
            b'0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
        super().__init__(base_u, p, q, d, mod_p, a24, key_len)

    def _decode_scalar_x448(self, k):
        k_list = [b for b in k]
        k_list[0] &= 252
        k_list[55] |= 128
        return self._decode_little_endian(k_list)

    def x448(self, k, u):
        k = self._decode_scalar_x448(k)
        u = self._decode_u_coordinate(u)
        res = self._scalar_multiplication(k, u)
        return self._encode_u_coordinate(int(res))

    def get_public_key(self, private_key):
        return self.x448(private_key, self.base)

    def encode(self, public_key):
        return b'\xff' + public_key

    def decode(self, encoded_public_key):
        return encoded_public_key[1:]

    def diffie_hellman(self, private_key, public_key):
        return self.x448(private_key, public_key)
