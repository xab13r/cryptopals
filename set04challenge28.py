'''

Matasano Crypto Challenges
Set 04 - Challenge 28

IMPLEMENT A SHA-1 KEYED MAC

'''

import struct
import hashlib
from os import urandom as get_random_bytes


def _left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff


def _process_chunk(chunk, h0, h1, h2, h3, h4):
    # Process the message in successive 512-bit (64 bytes) chunks
    assert len(chunk) == 64

    w = [0] * 80

    for i in range(16):
        w[i] = struct.unpack(b'>I', chunk[i * 4:i * 4 + 4])[0]

    for i in range(16, 80):
        w[i] = _left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

    a = h0
    b = h1
    c = h2
    d = h3
    e = h4

    for i in range(80):
        if 0 <= i <= 19:
            f = d ^ (b & (c ^ d))
            k = 0x5a827999
        elif 20 <= i <= 39:
            f = b ^ c ^ d
            k = 0x6ed9eba1
        elif 40 <= i <= 59:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8f1bbcdc
        elif 60 <= i <= 79:
            f = b ^ c ^ d
            k = 0xca62c1d6

        a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k +
                          w[i]) & 0xffffffff, a, _left_rotate(b, 30), c, d)

    # Add this chunk's hash to result so far
    h0 = (h0 + a) & 0xffffffff
    h1 = (h1 + b) & 0xffffffff
    h2 = (h2 + c) & 0xffffffff
    h3 = (h3 + d) & 0xffffffff
    h4 = (h4 + e) & 0xffffffff

    return h0, h1, h2, h3, h4


class SHA1Hash():
    # The message digest is a 160-bit (20 bytes) quantity
    digest_size = 20
    # Block size, the message lenth is a 64-bit (8 bytes) quantity
    block_size = 64

    def __init__(self):
        # Initialize variable
        self._unprocessed = b''
        self._message_byte_length = 0
        self._h = (
            0x67452301,
            0xefcdab89,
            0x98badcfe,
            0x10325476,
            0xc3d2e1f0,
        )

    def process(self, message):
        chunk = self._unprocessed + message  # + 64 - len(self._unprocessed)

        while len(chunk) == 64:
            self._h = _process_chunk(chunk, *self._h)
            self._message_byte_length += 64
            chunk = message

        self._unprocessed = chunk
        return self

    def digest(self):
        return b''.join(struct.pack(b'>I', h) for h in self._produce_digest())

    def hexdigest(self):
        return '%08x%08x%08x%08x%08x' % self._produce_digest()

    def _produce_digest(self):
        message = self._unprocessed
        message_byte_length = self._message_byte_length + len(message)

        # Append the bit '1' to the message
        message += b'\x80'

        # Append 0 <= k <= 512 bits '0', so the message length is congruent to 56 (mod 64)
        message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)

        # Append length of message (before pre-processing) as 64-bit big-endian integer
        message_bit_length = message_byte_length * 8
        message += struct.pack(b'>Q', message_bit_length)

        # Process the final chunk
        h = _process_chunk(message[:64], *self._h)
        if len(message) == 64:
            return h

        return _process_chunk(message[64:], *h)

def auth_SHA1(key, message):
    return SHA1Hash().process(key + message).hexdigest()


def main():
    m1 = b'YELLOW SUBMARINE'
    m2 = b'The quick brown fox jumps over the lazy dog'
    expected_sha1_m1 = hashlib.sha1(m1).hexdigest()
    expected_sha1_m2 = hashlib.sha1(m2).hexdigest()
    sha1_m1 = SHA1Hash().process(m1).hexdigest()
    sha1_m2 = SHA1Hash().process(m2).hexdigest()
    print("Verify SHA-1 implementation works as expected")
    if sha1_m1 == expected_sha1_m1 and sha1_m2 == expected_sha1_m2:
        print("\nMessage 1: ", m1)
        print("Expected SHA1:", expected_sha1_m1)
        print("Calculated SHA1:", sha1_m1)
        print("\nMessage 2: ", m2)
        print("Expected SHA1:", expected_sha1_m2)
        print("Calculated SHA1:", sha1_m2)
        print("--- Success ---")
    else:
        raise Exception("*** FAILED ***")

    print("Verify Athenticated SHA-1 implementation works as expected:")
    m = b'The quick brown fox jumps over the lazy dog'
    key = get_random_bytes(16)
    auth_sha1_m = auth_SHA1(key, m)
    expected_auth_sha1_m = hashlib.sha1(key + m).hexdigest()
    
    if auth_sha1_m == expected_auth_sha1_m:
        print("\nMessage: ", m)
        print("Key:", key)
        print("Expected Auth_SHA1:", expected_auth_sha1_m)
        print("Calculated Auth_SHA1:", auth_sha1_m)
        print("--- Success ---")
    else:
        raise Exception("*** FAILED ***")

if __name__ == "__main__":
    main()
