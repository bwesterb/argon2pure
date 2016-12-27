import unittest

import binascii
import itertools

import argon2pure

from six.moves import range

import argon2  # argon2-cffi

class TestArgon(unittest.TestCase):
    def _test(self, time_cost, memory_cost, parallelism):
        for type_code, version in itertools.product(
                (argon2pure.ARGON2D, argon2pure.ARGON2I, argon2pure.ARGON2ID),
                (0x10, 0x13)):
            cffi_type = {argon2pure.ARGON2I: argon2.Type.I,
                         argon2pure.ARGON2D: argon2.Type.D,
                         argon2pure.ARGON2ID: argon2.Type.ID}[type_code]
            self.assertEqual(
                    argon2.low_level.hash_secret_raw(
                        b'password', b'saltysaltsaltysalt',
                        time_cost, memory_cost, parallelism, 32,
                        cffi_type, version=version),
                    argon2pure.argon2(
                        b'password', b'saltysaltsaltysalt',
                        time_cost, memory_cost, parallelism, 32,
                        b'', b'', type_code, version=version))

    def test_base_parameters(self):
        for time_cost in range(1, 2):
            for parallelism in range(1, 2):
                for memory_cost in range(8*parallelism, 8*parallelism+10):
                    self._test(time_cost, memory_cost, parallelism)
    def test_high_mem(self):
        for exponent in range(4):
            memory_cost = 16 + (4 ** exponent)
            self._test(2, memory_cost, 2)

    # def test_heavy_load(self):
    #     # make sure pool workers are cleaned up after call,
    #     # so they don't accumulate until pool is GC'ed
    #     for _ in range(200):
    #         argon2(b"p", b"s", time_cost=1, memory_cost=16, parallelism=2)

class TestBlake2b(unittest.TestCase):
    def test_blake2b_keyed(self):
        cur = b'!'
        for i in range(1,10):
            cur = argon2pure.Blake2b(cur, key=cur[:i]).digest()
        self.assertEqual(binascii.hexlify(cur),
            b'ce91a1c91d8865a36c090c576a3f99d2b5e3e29cd17b35fdb919bf1ee640f5b1'
            b'2285d26e9727b48c4004624b83d6bdea3e3354e491e2ffb40b1517cc39ba9b97')
    def test_blake2b_unkeyed(self):
        cur = b''
        for i in range(100):
            cur = argon2pure.Blake2b(cur).digest()
        self.assertEqual(argon2pure.Blake2b(cur).hexdigest(),
            b'fbf206a49876bb827af18cd6ddacb72ad017570984126d184138ac7a04635925'
            b'87b66c9f380ce661861be15d19d5b8a15ad165126a007819f00db0148e71ca39')
    def test_blake2b_various(self):
        cur = b'!'
        for i in range(1, 64):
            cur = argon2pure.Blake2b(cur, digest_length=i, key=cur[:i]).digest()
        self.assertEqual(binascii.hexlify(cur),
            b'e2cb742f0045a56dee6db055645020bc5243e8f929c82a4195fed39fd7a9c5b'
            b'197247fb6f4a346bf0d97dde730b9325677ac24e5752ad49d3fd80083d4cc57')

if __name__ == '__main__':
    unittest.main()
