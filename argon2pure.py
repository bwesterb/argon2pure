""" Pure Python implementation of the Argon2 password hash.

    Bas Westerbaan  <bas@westerbaan.name> """

import six
from six.moves import range
from six import BytesIO

import struct
import binascii

__all__ = [
    'argon2',
    'ARGON2D',
    'ARGON2I',
    'Argon2Error',
    'Argon2ParameterError']

ARGON2I = 1
ARGON2D = 0

class Argon2Error(Exception):
    pass

class Argon2ParameterError(Argon2Error):
    pass

def argon2(password, salt, time_cost, memory_cost, parallelism,
                tag_length, secret=b'', associated_data=b'', type_code=1):
    # Compute the pre-hasing digest
    if parallelism < 0:
        raise Argon2ParameterError("parallelism must be strictly positive")
    if time_cost < 0:
        raise Argon2ParameterError("time_cost must be strictly positive")
    if memory_cost < 8 * parallelism:
        raise Argon2ParameterError("memory_cost can't be less than 8"
                                    " times the number of lanes")

    h = Blake2b()
    h.update(struct.pack("<iiiiii", parallelism,
                                    tag_length,
                                    memory_cost,
                                    time_cost,
                                    0x10,
                                    type_code))
    h.update(struct.pack("<i", len(password)))
    h.update(password)
    h.update(struct.pack("<i", len(salt)))
    h.update(salt)
    h.update(struct.pack("<i", len(secret)))
    h.update(secret)
    h.update(struct.pack("<i", len(associated_data)))
    h.update(associated_data)
    H0 = h.digest()

    m_prime = (memory_cost // (4 * parallelism)) * (4 * parallelism)
    q = m_prime / parallelism  # lane_length
    segment_length = q / 4

    if type_code not in (0, 1):
        raise Argon2ParameterError("type_code %s not supported" % type_code)

    # Allocate the matrix.
    B = [[None for j in range(q)] for i in range(parallelism)]

    for t in range(time_cost):
        if t == 0:
            # Compute first two columns
            for i in range(parallelism):
                B[i][0] = _H_prime(H0 + struct.pack('<II', 0, i), 1024)
                B[i][1] = _H_prime(H0 + struct.pack('<II', 1, i), 1024)
            j_start = 2
        else:
            j_start = 0

        if type_code == ARGON2I:
            pseudo_rands_by_lane = None

        # Compute remaining columns
        for j in range(j_start, q):
            segment = j // (q / 4)  # index of the slice/segment
            index = j % (q / 4)     # index within the segment/slice

            # Argon2i computes a bunch of pseudo-random numbers
            # for every segment.
            if type_code == ARGON2I and (j % segment_length == 0
                                        or pseudo_rands_by_lane is None):
                pseudo_rands_by_lane = []
                for l in range(parallelism):
                    # See `generate_addresses' in reference implementation
                    # and section 3.3 of the specification.
                    pseudo_rands = []
                    ctr = 0  # `i' in the specification
                    while len(pseudo_rands) < segment_length:
                        ctr += 1
                        address_block = _compress('\0'*1024,
                                        _compress('\0'*1024,
                                            struct.pack('<QQQQQQQ',
                                                t, l, segment, m_prime,
                                                time_cost, type_code, ctr)
                                            + '\0'*968))
                        for addr_i in range(0, 1024, 8):
                            pseudo_rands.append(
                                    struct.unpack('<II',
                                        address_block[addr_i:addr_i+8]))
                    pseudo_rands_by_lane.append(pseudo_rands)

            for i in range(parallelism):
                # See `section 3.3. Indexing' of argon2 spec.
                # First, we derive two pseudo-random values from the current
                # state.  This is where Argon2i and Argon2d differ.
                if type_code == ARGON2D:
                    J1, J2 = struct.unpack_from('<II', B[i][(j-1)%q][:8])
                elif type_code == ARGON2I:
                    J1, J2 = pseudo_rands_by_lane[i][index]
                else:
                    assert False

                # Using the pseudo-random J1 and J2, we pick a reference
                # block to mix with the previous one to create the next.
                i_prime = J2 % parallelism

                if t == 0:
                    if segment == 0:
                        ref_area_size = index - 1  # TODO same as next case?
                    elif i == i_prime:  # same_lane
                        ref_area_size = j - 1
                    elif index == 0:
                        ref_area_size = segment * segment_length - 1
                    else:
                        ref_area_size = segment * segment_length
                elif i == i_prime:  # same_lane
                    ref_area_size = q - segment_length + index - 1
                elif index == 0:
                    ref_area_size = q - segment_length - 1
                else:
                    ref_area_size = q - segment_length

                rel_pos = (J1 ** 2) >> 32
                rel_pos = ref_area_size - 1 - ((ref_area_size * rel_pos) >> 32)
                start_pos = 0

                if t != 0 and segment != 3:
                    start_pos = (segment + 1) * segment_length
                j_prime = (start_pos + rel_pos) % q

                # Mix the previous and reference block to create
                # the next block.
                B[i][j] = _compress(B[i][(j-1)%q], B[i_prime][j_prime])

    B_final = b'\0' * 1024

    for i in range(parallelism):
        B_final = xor(B_final, B[i][q-1])

    return _H_prime(B_final, tag_length)


if six.PY3:
    def xor(a, b):
        return bytes([a[i] ^ b[i] for i in range(len(a))])
else:
    def xor(a, b):
        return ''.join([chr(ord(a[i]) ^ ord(b[i])) for i in range(len(a))])


def _compress(X, Y):
    """ Argon2's compression function G.

    This function is based on Blake2's compression function.
    For the definition, see section 3.4 of Argon2's specification. """
    R = xor(X, Y)
    Q = []
    Z = [None]*64
    for i in range(0, 64, 8):
        Q.extend(_P(R[i    *16:(i+1)*16],
                    R[(i+1)*16:(i+2)*16],
                    R[(i+2)*16:(i+3)*16],
                    R[(i+3)*16:(i+4)*16],
                    R[(i+4)*16:(i+5)*16],
                    R[(i+5)*16:(i+6)*16],
                    R[(i+6)*16:(i+7)*16],
                    R[(i+7)*16:(i+8)*16]))
    for i in range(8):
        out = _P(Q[i], Q[i+8], Q[i+16], Q[i+24],
                    Q[i+32], Q[i+40], Q[i+48], Q[i+56])
        for j in range(8):
            Z[i + j*8] = out[j]
    return xor(b''.join(Z), R)


def _P(S0, S1, S2, S3, S4, S5, S6, S7):
    """ Permutation used in Argon2's compression function G.

    It is a modification of the permutation used in Blake2.
    See Appendix A of the specification of Argon2. """
    S = (S0, S1, S2, S3, S4, S5, S6, S7)
    v = [None] * 16
    for i in range(8):
        tmp1, tmp2 = struct.unpack_from('<QQ', S[i])
        v[2*i] = tmp1
        v[2*i+1] = tmp2
    _G(v, 0, 4, 8, 12)
    _G(v, 1, 5, 9, 13)
    _G(v, 2, 6, 10, 14)
    _G(v, 3, 7, 11, 15)
    _G(v, 0, 5, 10, 15)
    _G(v, 1, 6, 11, 12)
    _G(v, 2, 7, 8, 13)
    _G(v, 3, 4, 9, 14)
    ret =  [struct.pack("<QQ", v[2*i], v[2*i+1]) for i in range(8)]
    return ret


def _G(v, a, b, c, d):
    """ Quarter-round of the permutation used in the compression of Argon2.

    It is a modification of the quarter-round used in Blake2, which in turn
    is a modification of ChaCha.  See Appendix A of the specification of
    Argon2. """
    v[a] = (v[a] + v[b] + 2 * (v[a] & 0xffffffff) * (v[b] & 0xffffffff)
                ) & 0xffffffffffffffff
    tmp = v[d] ^ v[a]
    v[d] = (tmp >> 32) | ((tmp << 32) & 0xffffffffffffffff)
    v[c] = (v[c] + v[d] + 2 * (v[c] & 0xffffffff) * (v[d] & 0xffffffff)
                ) & 0xffffffffffffffff
    tmp = v[b] ^ v[c]
    v[b] = (tmp >> 24) | ((tmp << 40) & 0xffffffffffffffff)
    v[a] = (v[a] + v[b] + 2 * (v[a] & 0xffffffff) * (v[b] & 0xffffffff)
                ) & 0xffffffffffffffff
    tmp = v[d] ^ v[a]
    v[d] = (tmp >> 16) | ((tmp << 48) & 0xffffffffffffffff)
    v[c] = (v[c] + v[d] + 2 * (v[c] & 0xffffffff) * (v[d] & 0xffffffff)
                ) & 0xffffffffffffffff
    tmp = v[b] ^ v[c]
    v[b] = (tmp >> 63) | ((tmp << 1) & 0xffffffffffffffff)


def _H_prime(X, tag_length):
    """ Blake2b turned into a "variable-length hash function".

        See definition of H' in section 3.2 of the argon2 spec. """
    if tag_length <= 64:
        return Blake2b(struct.pack('<I', tag_length) + X,
                       digest_length=tag_length).digest()
    buf = BytesIO()
    V = Blake2b(struct.pack('<I', tag_length) + X).digest()  # V_1
    buf.write(V[:32])
    todo = tag_length - 32
    while todo > 64:  
        V = Blake2b(V).digest()  # V_2, ..., V_r
        buf.write(V[:32])
        todo -= 32
    buf.write(Blake2b(V, digest_length=todo).digest())  # V_{r+1}
    return buf.getvalue()

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

    def __init__(self, data=b'', key=b'', digest_length=64):
        # default parameter block for sequential Blake2b with 128 byte
        # digest and key.
        assert 0 <= len(key) <= 128
        assert 0 < digest_length <= 64
        P = [0x0000000001010000, 0, 0, 0, 0, 0, 0, 0]
        P[0] |= len(key) << 8
        P[0] |= digest_length
        self._digest_length = digest_length
        self._buf = b''  # data that didn't fit in a block yet
        self._h = [self.IV[i] ^ P[i] for i in range(8)]  # current hash
        self._t = [0, 0]  # counter
        self._f = [0, 0]  # finalization flags
        self._N = 0
        self.finalized = False


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
            self._digest = struct.pack('<8Q', *self._h)[:self._digest_length]
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
