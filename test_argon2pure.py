import unittest

import binascii

import argon2pure

class TestBlake2b(unittest.TestCase):
    def test_blake2b_keyed(self):
        cur = b'!'
        for i in xrange(1,10):
            cur = argon2pure.Blake2b(cur, key=cur[:i]).digest()
        self.assertEqual(binascii.hexlify(cur),
            'ce91a1c91d8865a36c090c576a3f99d2b5e3e29cd17b35fdb919bf1ee640f5b1'
            '2285d26e9727b48c4004624b83d6bdea3e3354e491e2ffb40b1517cc39ba9b97')
    def test_blake2b_unkeyed(self):
        cur = b''
        for i in xrange(100):
            cur = argon2pure.Blake2b(cur).digest()
        self.assertEqual(argon2pure.Blake2b(cur).hexdigest(),
            'fbf206a49876bb827af18cd6ddacb72ad017570984126d184138ac7a04635925'
            '87b66c9f380ce661861be15d19d5b8a15ad165126a007819f00db0148e71ca39')
    def test_blake2b_various(self):
        import pyblake2
        cur = b'!'
        for i in xrange(1, 64):
            cur = argon2pure.Blake2b(cur, digest_length=i, key=cur[:i]).digest()
        self.assertEqual(binascii.hexlify(cur),
            'e2cb742f0045a56dee6db055645020bc5243e8f929c82a4195fed39fd7a9c5b'
            '197247fb6f4a346bf0d97dde730b9325677ac24e5752ad49d3fd80083d4cc57')

if __name__ == '__main__':
    unittest.main()
