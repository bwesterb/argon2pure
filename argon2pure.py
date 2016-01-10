""" Pure Python implementation of the Argon2 password hash. """

from six.moves import range

import struct
import binascii

class Blake2b(object):
    """ Minimal implementation of Blake2b, as required by Argon2. """
    
    IV = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
          0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
          0x510e527fade682d1, 0x9b05688c2b3e6c1f,
          0x1f83d9abfb41bd6b, 0x5be0cd19137e2179] 

    SIGMA = ((0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15),
             (14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3),
             (11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4),
             (7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8),
             (9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13),
             (2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9),
             (12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11),
             [13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
             (6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5),
             (10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0),
             (0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15),
             (14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3))

    def __init__(self, data=b'', key=b''):
        # default parameter block for sequential Blake2b with 128 byte
        # digest and key.
        P = [0x0000000001010040, 0, 0, 0, 0, 0, 0, 0]
        P[0] |= (len(key) & 0xff) << 8
        self._buf = b''  # data that didn't fit in a block yet
        self._h = [self.IV[i] ^ P[i] for i in range(8)]  # current hash
        self._t = [0, 0]  # counter
        self._f = [0, 0]  # finalization flags
        self._N = 0
        self.finalized = False

        assert 0 <= len(key) <= 128

        if key:
            self.update(key + b'\0' * (128 - len(key)))
        if data:
            self.update(data)

    def update(self, data):
        assert not self.finalized
        i = 0
        l = len(data)

        if len(self._buf) + l <= 128:
            # We do not have enough data for one compression.  Store it in
            # the buffer and return.
            self._buf += data
            return

        # First, use the buffer
        self._compress(self._buf + data[:128 - len(self._buf)], 128)
        i = 128 - len(self._buf)

        # Now take as many blocks from data as we can.
        while l - i > 128:
            self._compress(data[i:i+128], 128)
            i += 128

        # Put the rest in the buffer
        self._buf = data[i:]

    def final(self):
        if not self.finalized:
            n_remaining = len(self._buf)
            buf = self._buf + b'\0' * (128 - len(self._buf))
            self._f[0] = 0xffffffffffffffff
            self._compress(buf, n_remaining)
            self._digest = struct.pack('<8Q', *self._h)
            self.finalized = True
        return self._digest
    digest = final

    def hexdigest(self):
        return binascii.hexlify(self.final())

    def _compress(self, block, n_data):
        self._N += n_data
        self._t[0] = self._N & 0xffffffffffffffff
        self._t[1] = self._N >> 64
        m = struct.unpack_from('<16Q', block)
        v = self._h + self.IV
        v[12] ^= self._t[0]
        v[13] ^= self._t[1]
        v[14] ^= self._f[0]
        v[15] ^= self._f[1]
        for r in range(12):
            Blake2b._G(v, m, r, 0, 0, 4, 8, 12)
            Blake2b._G(v, m, r, 1, 1, 5, 9, 13)
            Blake2b._G(v, m, r, 2, 2, 6, 10, 14)
            Blake2b._G(v, m, r, 3, 3, 7, 11, 15)
            Blake2b._G(v, m, r, 4, 0, 5, 10, 15)
            Blake2b._G(v, m, r, 5, 1, 6, 11, 12)
            Blake2b._G(v, m, r, 6, 2, 7, 8, 13)
            Blake2b._G(v, m, r, 7, 3, 4, 9, 14)
        self._h = [self._h[i] ^ v[i] ^ v[i+8] for i in range(8)]

    @staticmethod
    def _G(v, m, r, i, a, b, c, d):
        v[a] = (v[a] + v[b] + m[Blake2b.SIGMA[r][2*i]]) & 0xffffffffffffffff
        tmp = v[d] ^ v[a]
        v[d] = (tmp >> 32) | ((tmp << 32) & 0xffffffffffffffff)
        v[c] = (v[c] + v[d]) & 0xffffffffffffffff
        tmp = v[b] ^ v[c]
        v[b] = (tmp >> 24) | ((tmp << 40) & 0xffffffffffffffff)
        v[a] = (v[a] + v[b] + m[Blake2b.SIGMA[r][2*i+1]]) & 0xffffffffffffffff
        tmp = v[d] ^ v[a]
        v[d] = (tmp >> 16) | ((tmp << 48) & 0xffffffffffffffff)
        v[c] = (v[c] + v[d]) & 0xffffffffffffffff
        tmp = v[b] ^ v[c]
        v[b] = (tmp >> 63) | ((tmp << 1) & 0xffffffffffffffff)
    
