'''

Matasano Crypto Challenges
Set 03 - Challenge 24

CREATE THE MT19937 STREAM CIPHER AND BREAK IT

'''

from set03challenge21 import MT19937
from Crypto.Random.random import randint
from Crypto.Random import get_random_bytes
from set01challenge02 import xor_strings
import struct
from time import time


class MT19937_cipher:

    def __init__(self, seed):
        self.rng = MT19937(seed)
        self.rng_out = self.rng.extract_number()

    def encrypt(self, plaintext):
        keystream = b''

        while len(keystream) < len(plaintext):
            # Pack each RNG output to a 32-bit Big Endian bytes string
            keystream += struct.pack('>L', self.rng_out)

        if len(keystream) > len(plaintext):
            keystream = keystream[:len(plaintext)]

        # XOR the keystream with the plaintext
        return xor_strings(keystream, plaintext)

    def decrypt(self, ciphertext):
        # Because of the XOR operation, decryption and encryption are the same
        return self.encrypt(ciphertext)


def test_MT19937_cipher(test_plaintext):
    cipher = MT19937_cipher(randint(0, 2**16 - 1))
    ciphertext = cipher.encrypt(test_plaintext)
    plaintext = cipher.decrypt(ciphertext)
    if plaintext != test_plaintext:
        raise Exception("*** FAILED ***")
    print("--- Encryption module is working as expected...")


def crack_MT19937_cipher(ciphertext, known_plaintext):

    for seed in range(2**16):
        possible_plaintext = MT19937_cipher(seed).decrypt(ciphertext)

        if known_plaintext in possible_plaintext:
            print("--- Cracked ---")
            print("Seed found:", seed)
            return seed

    raise Exception("*** FAILED***\n*** The seed wa not a 16 bit number ***")


def crack_MT19937_seed(ciphertext, known_plaintext):
    guessed_seed = int(time()) + 100
    current_plaintext = MT19937_cipher(guessed_seed).decrypt(ciphertext)
    print("Reversing time...")
    while (known_plaintext not in current_plaintext):
        guessed_seed -= 1
        current_plaintext = MT19937_cipher(guessed_seed).decrypt(ciphertext)

    print("--- Cracked ---")
    print("RNG has been seeded with current time")
    print("Seed found:", guessed_seed)
    return guessed_seed


def main():
    # 1. Write the function that does this for MT19937 using a 16-bit seed. Verify that you can encrypt and decrypt properly.
    print("\n1. Verifying MT19937_cipher is working as expected")
    test_plaintext = b'This is a random line that we would like to encrypt'
    test_MT19937_cipher(test_plaintext)

    print("\n2. Recover encryption seed from an expanded known plaintext")
    # 2. Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters) prefixed by a random number of random characters. From the ciphertext, recover the "key" (the 16 bit seed).
    seed = randint(0, 2**16)
    random_prefix = get_random_bytes(randint(0, 16))
    target = b'AAAAAAAAAAAAAA'
    ciphertext = MT19937_cipher(seed).encrypt(random_prefix + target)
    cracked_seed = crack_MT19937_cipher(ciphertext, target)

    print("\n3. Check if MT19937 has been seeded with current time")
    # 3. Use the same idea to generate a random "password reset token" using MT19937 seeded from the current time. Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with the current time.
    seed = int(time())
    random_prefix = get_random_bytes(randint(0, 16))
    target = b'username'
    random_suffix = b';password_reset=true'
    plaintext = random_prefix + target + random_suffix
    ciphertext = MT19937_cipher(seed).encrypt(plaintext)
    cracked_seed = crack_MT19937_seed(ciphertext, target)


if __name__ == "__main__":
    main()
