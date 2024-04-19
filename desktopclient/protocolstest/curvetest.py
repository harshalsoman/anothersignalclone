import unittest

from protocols.curve import Curve25519, Curve448


class TestSecureEllipticCurve(unittest.TestCase):

    def setUp(self):
        self.x25519_base = bytes.fromhex('0900000000000000000000000000000000000000000000000000000000000000')
        self.x448_base = bytes.fromhex('0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
        self.x25519_f = bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffff')

    def test_vector_x25519_1(self):
        k = bytes.fromhex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4')
        u = bytes.fromhex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c')
        r = bytes.fromhex('c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552')
        self.assertEqual(Curve25519().x25519(k, u), r)

    def test_vector_x25519_2(self):
        k = bytes.fromhex('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d')
        u = bytes.fromhex('e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493')
        r = bytes.fromhex('95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957')
        self.assertEqual(Curve25519().x25519(k, u), r)

    def test_vector_x448_1(self):
        k = bytes.fromhex('3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3')
        u = bytes.fromhex('06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086')
        r = bytes.fromhex('ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f')
        self.assertEqual(Curve448().x448(k, u), r)

    def test_vector_x448_2(self):
        k = bytes.fromhex('203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f')
        u = bytes.fromhex('0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db')
        r = bytes.fromhex('884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d')
        self.assertEqual(Curve448().x448(k, u), r)

    def test_1_iteration_x25519(self):
        k = self.x25519_base
        u = self.x25519_base
        r = bytes.fromhex('422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079')
        self.assertEqual(Curve25519().x25519(k, u), r)

    def test_1000_iteration_x25519(self):
        k = self.x25519_base
        u = self.x25519_base
        res = bytes.fromhex('684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51')
        for i in range(1000):
            r = Curve25519().x25519(k, u)
            u = k
            k = r
        self.assertEqual(k, res)

    def t_1000000_iteration_x25519(self):
        "Removed from test as it takes a long time"
        k = self.x25519_base
        u = self.x25519_base
        res = bytes.fromhex('7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424')
        for i in range(1000000):
            r = Curve25519().x25519(k, u)
            u = k
            k = r
        self.assertEqual(k, res)

    def test_1_iteration_x448(self):
        k = self.x448_base
        u = self.x448_base
        r = bytes.fromhex('3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113')
        self.assertEqual(Curve448().x448(k, u), r)

    def test_1000_iteration_x448(self):
        k = self.x448_base
        u = self.x448_base
        res = bytes.fromhex('aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38')
        for i in range(1000):
            r = Curve448().x448(k, u)
            u = k
            k = r
        self.assertEqual(k, res)

    def t_1000000_iteration_x448(self):
        "Removed from test as it takes a long time"
        k = self.x448_base
        u = self.x448_base
        res = bytes.fromhex('077f453681caca3693198420bbe515cae0002472519b3e67661a7e89cab94695c8f4bcd66e61b9b9c946da8d524de3d69bd9d9d66b997e37')
        for i in range(1000000):
            r = Curve25519().x25519(k, u)
            u = k
            k = r
        self.assertEqual(k, res)

    def test_public_key_x25519(self):
        alice_private_key = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
        alice_public_key = bytes.fromhex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
        bob_private_key = bytes.fromhex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
        bob_public_key = bytes.fromhex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')

        self.assertEqual(alice_public_key, Curve25519().get_public_key(alice_private_key))
        self.assertEqual(bob_public_key, Curve25519().get_public_key(bob_private_key))

    def test_diffie_hellman_x448(self):
        alice_private_key = bytes.fromhex('9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b')
        alice_public_key = bytes.fromhex('9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0')
        bob_private_key = bytes.fromhex('1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d')
        bob_public_key = bytes.fromhex('3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609')

        self.assertEqual(alice_public_key, Curve448().get_public_key(alice_private_key))
        self.assertEqual(bob_public_key, Curve448().get_public_key(bob_private_key))

    def test_diffie_hellman_x25519(self):
        alice_private_key = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
        alice_public_key = bytes.fromhex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
        bob_private_key = bytes.fromhex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
        bob_public_key = bytes.fromhex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
        shared_secret_key = bytes.fromhex('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')

        alice_secret_key = Curve25519().x25519(alice_private_key, bob_public_key)
        bob_secret_key = Curve25519().x25519(bob_private_key, alice_public_key)
        self.assertEqual(alice_secret_key, shared_secret_key)
        self.assertEqual(bob_secret_key, shared_secret_key)

    def test_diffie_hellman_x448(self):
        alice_private_key = bytes.fromhex('9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b')
        alice_public_key = bytes.fromhex('9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0')
        bob_private_key = bytes.fromhex('1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d')
        bob_public_key = bytes.fromhex('3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609')
        shared_secret_key = bytes.fromhex('07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d')

        alice_secret_key = Curve448().x448(alice_private_key, bob_public_key)
        bob_secret_key = Curve448().x448(bob_private_key, alice_public_key)
        self.assertEqual(alice_secret_key, shared_secret_key)
        self.assertEqual(bob_secret_key, shared_secret_key)
