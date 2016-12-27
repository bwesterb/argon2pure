""" Pure Python implementation of the Argon2 password hash.

    If you can, use the `argon2_cffi' or `argon2' bindings.

    Bas Westerbaan <bas@westerbaan.name> """


import six
from six.moves import range
from six import BytesIO

import struct
import binascii
import multiprocessing
import multiprocessing.dummy

__all__ = [
    'argon2',
    'ARGON2D',
    'ARGON2I',
    'ARGON2_DEFAULT_VERSION',
    'ARGON2_VERSIONS',
    'Argon2Error',
    'Argon2ParameterError']

ARGON2D  = 0
ARGON2I  = 1
ARGON2ID = 2

ARGON2_VERSIONS = (0x10, 0x13)
ARGON2_DEFAULT_VERSION = ARGON2_VERSIONS[-1]
ARGON2_TYPES = (ARGON2D, ARGON2I, ARGON2ID)

class Argon2Error(Exception):
    pass

class Argon2ParameterError(Argon2Error):
    pass

def argon2(password, salt, time_cost, memory_cost, parallelism,
                tag_length=32, secret=b'', associated_data=b'',
                type_code=ARGON2I, threads=None, version=ARGON2_DEFAULT_VERSION,
                use_threads=False):
    """ Compute the Argon2 hash for *password*.

    :param bytes password: Password to hash
    :param bytes salt: A salt.  Should be random and different for each
        password.
    :param int time_cost: Number of iterations to use.
    :param int memory_cost: Amount of kibibytes of memory to use.
    :param int parallelism: Amount of threads that can contribute to
        the computation of the hash at the same time.

    Optional arguments:

    :param int tag_length: Length of the hash returned
    :param bytes secret: Optional secret to differentiate hash
    :param bytes associated_data: Optional associated data
    :param int type: variant of argon2 to use.  Either ARGON2I or ARGON2D
    :param int threads: number of threads to use to compute the hash.
    :param bool use_threads: if true, signal multiprocessing to use threads
        rather than processes.
    :param int version: version of argon2 to use.  At the moment either
        0x10 for v1.0 or 0x13 for v1.3

    :rtype: bytes """
    if threads is None:
        threads = parallelism
    if parallelism <= 0:
        raise Argon2ParameterError("parallelism must be strictly positive")
    if threads <= 0:
        raise Argon2ParameterError("threads must be strictly positive")
    if time_cost <= 0:
        raise Argon2ParameterError("time_cost must be strictly positive")
    if memory_cost < 8 * parallelism:
        raise Argon2ParameterError("memory_cost can't be less than 8"
                                    " times the number of lanes")
    if type_code not in ARGON2_TYPES:
        raise Argon2ParameterError("type_code %s not supported" % type_code)
    if version not in ARGON2_VERSIONS:
        raise Argon2ParameterError("version %s not supported" % version)

    threads = min(parallelism, threads)

    if threads == 1:
        worker_pool = None
    else:
        if use_threads:
            Pool = multiprocessing.dummy.Pool
        else:
            Pool = multiprocessing.Pool
        worker_pool = Pool(processes=threads)

    # Compute the pre-hasing digest
    h = Blake2b()
    h.update(struct.pack("<iiiiii", parallelism,
                                    tag_length,
                                    memory_cost,
                                    time_cost,
                                    version,
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
    q = m_prime // parallelism  # lane_length
    segment_length = q // 4

    # Allocate the matrix.
    B = [[None for j in range(q)] for i in range(parallelism)]

    # The blocks in Argon2 are arranged in a matrix.  For each thread,
    # there is a row, which is also called a lane.  The number of
    # columns depends on the memory_cost.
    # There will be time_cost passes over the whole matrix.
    # The colums are put into groups of four, called slices.
    # The intersection of a lane with a slice is called a segment.
    # The matrix is filled one slice at the time.  The segments within
    # a slice can be computed in parallel.
    for t in range(time_cost):
        for segment in range(4):
            if not worker_pool:
                for i in range(parallelism):
                    _fill_segment(B, t, segment, i, type_code, segment_length,
                                H0, q, parallelism, m_prime, time_cost, version)
                continue

            handles = [None]*parallelism
            for i in range(parallelism):
                handles[i] = worker_pool.apply_async(_fill_segment,
                            (B, t, segment, i, type_code, segment_length, H0,
                                q, parallelism, m_prime, time_cost, version))
            for i in range(parallelism):
                new_blocks = handles[i].get()
                for index in range(segment_length):
                    B[i][segment * segment_length + index] = new_blocks[index]

    if worker_pool:
        # don't let workers sit around until pool is GC'd
        worker_pool.close()

    B_final = b'\0' * 1024

    for i in range(parallelism):
        B_final = xor1024(B_final, B[i][q-1])

    return _H_prime(B_final, tag_length)

def _fill_segment(B, t, segment, i, type_code, segment_length, H0,
                        q, parallelism, m_prime, time_cost, version):
    # Argon2i computes a bunch of pseudo-random numbers
    # for every segment.
    data_independant = ((type_code == ARGON2I)
            or (type_code == ARGON2ID and t == 0 and segment <= 1))
    if data_independant:
        # See `generate_addresses' in reference implementation
        # and section 3.3 of the specification.
        pseudo_rands = []
        ctr = 0  # `i' in the specification
        while len(pseudo_rands) < segment_length:
            ctr += 1
            address_block = _compress(b'\0'*1024, _compress(b'\0'*1024,
                                struct.pack('<QQQQQQQ', t, i, segment, m_prime,
                                                    time_cost, type_code, ctr)
                                    + b'\0'*968))
            for addr_i in range(0, 1024, 8):
                pseudo_rands.append(struct.unpack('<II',
                            address_block[addr_i:addr_i+8]))

    for index in range(segment_length):
        j = segment * segment_length + index
        if t == 0 and j < 2:
            # First two columns are special.
            B[i][j] = _H_prime(H0 + struct.pack('<II', j, i), 1024)
            continue

        # See `section 3.3. Indexing' of argon2 spec.
        # First, we derive two pseudo-random values from the current
        # state.  This is where Argon2i and Argon2d differ.
        if data_independant:
            J1, J2 = pseudo_rands[index]
        else:
            J1, J2 = struct.unpack_from('<II', B[i][(j-1)%q][:8])

        # Using the pseudo-random J1 and J2, we pick a reference
        # block to mix with the previous one to create the next.
        i_prime = i if t == 0 and segment == 0 else J2 % parallelism

        if t == 0:
            if segment == 0 or i == i_prime:
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
        new_block = _compress(B[i][(j-1)%q], B[i_prime][j_prime])
        if t != 0 and version == 0x13:
            new_block = xor1024(B[i][j], new_block)
        B[i][j] = new_block

    # If we are run in a separate thread, then B is a copy.  Return changes.
    return B[i][segment*segment_length:(segment+1)*segment_length]


# xor1024: XOR two 1024 byte blocks with eachother.

if six.PY3:
    def xor1024(a, b):
        return (int.from_bytes(a, byteorder='little') ^
                int.from_bytes(b, byteorder='little')).to_bytes(
                                 1024, byteorder='little')
else:
    _1024B_STRUCT = struct.Struct('Q'*128)
    def xor1024(a, b):
        a2 = _1024B_STRUCT.unpack(a)
        b2 = list(_1024B_STRUCT.unpack(b))
        for i in xrange(128):
            b2[i] ^= a2[i]
        return _1024B_STRUCT.pack(*b2)

def _compress(X, Y):
    """ Argon2's compression function G.

    This function is based on Blake2's compression function.
    For the definition, see section 3.4 of Argon2's specification. """
    R = xor1024(X, Y)
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
    return xor1024(b''.join(Z), R)


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
    va, vb, vc, vd = v[a], v[b], v[c], v[d]
    va = (va + vb + 2 * (va & 0xffffffff) * (vb & 0xffffffff)
                ) & 0xffffffffffffffff
    tmp = vd ^ va
    vd = (tmp >> 32) | ((tmp & 0xffffffff) << 32)
    vc = (vc + vd + 2 * (vc & 0xffffffff) * (vd & 0xffffffff)
                ) & 0xffffffffffffffff
    tmp = vb ^ vc
    vb = (tmp >> 24) | ((tmp & 0xffffff) << 40)
    va = (va + vb + 2 * (va & 0xffffffff) * (vb & 0xffffffff)
                ) & 0xffffffffffffffff
    tmp = vd ^ va
    vd = (tmp >> 16) | ((tmp & 0xffff) << 48)
    vc = (vc + vd + 2 * (vc & 0xffffffff) * (vd & 0xffffffff)
                ) & 0xffffffffffffffff
    tmp = vb ^ vc
    vb = (tmp >> 63) | ((tmp << 1) & 0xffffffffffffffff)
    v[a], v[b], v[c], v[d] = va, vb, vc, vd


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
        va, vb, vc, vd = v[a], v[b], v[c], v[d]
        va = (va + vb + m[Blake2b.SIGMA[r][2*i]]) & 0xffffffffffffffff
        tmp = vd ^ va
        vd = (tmp >> 32) | ((tmp & 0xffffffff) << 32)
        vc = (vc + vd) & 0xffffffffffffffff
        tmp = vb ^ vc
        vb = (tmp >> 24) | ((tmp & 0xffffff) << 40)
        va = (va + vb + m[Blake2b.SIGMA[r][2*i+1]]) & 0xffffffffffffffff
        tmp = vd ^ va
        vd = (tmp >> 16) | ((tmp & 0xffff) << 48)
        vc = (vc + vd) & 0xffffffffffffffff
        tmp = vb ^ vc
        vb = (tmp >> 63) | ((tmp << 1) & 0xffffffffffffffff)
        v[a], v[b], v[c], v[d] = va, vb, vc, vd
