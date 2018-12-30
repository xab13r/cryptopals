'''

Matasano Crypto Challenges
Set 02 - Challenge 11

AN ECB/CBC DETECTION ORACLE

'''

import base64
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from set02challenge09 import pkcs7_padding
from set01challenge06 import slice_target
from set02challenge10 import cbc_module

key = b"YELLOW SUBMARINE"
iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


class ecb_module():

    def __init__(self):
        # Create cipher instance
        self.cipher = AES.new(key, AES.MODE_ECB)

    # ECB Encryption Method
    def ecb_encrypt(self, plaintext, key):
        # Slice plaintext into blocks
        plaintext_blocks = slice_target(plaintext, 16)
        # Initialize plaintext variable for padding
        plaintext_padded = b""
        # Apply PKCS7 Padding
        if len(plaintext_blocks[-1]) < 16:
            plaintext_blocks[-1] = pkcs7_padding(plaintext_blocks[-1], 16)
        # Add blocks together
        for i in plaintext_blocks:
            plaintext_padded += bytes(i)
        # Encrypt under given key
        return self.cipher.encrypt(plaintext_padded)

    # ECB Decryption Method
    def ecb_decrypt(self, ciphertext, key):
        # Slice ciphertext into blocks
        ciphertext_blocks = slice_target(ciphertext, 16)
        # Initialize plaintext list for blocks
        plaintext_blocks = [b"" for i in range(len(ciphertext_blocks))]
        # Decrypt each block and add it to the plaintext list
        for i in range(len(ciphertext_blocks)):
            plaintext_blocks[i] = self.cipher.decrypt(ciphertext_blocks[i])

        # Get last block and identify padding
        padding = plaintext_blocks[-1][-1]
        # Remove padding from last block
        plaintext_blocks[-1] = plaintext_blocks[-1][:-padding]
        # Initialize plaintext variable
        plaintext = b""
        # Add blocks together
        for i in plaintext_blocks:
            plaintext += i
        return plaintext


def encryption_oracle(plaintext):
    random_key = get_random_bytes(16)
    random_iv = get_random_bytes(16)
    # print("Random key:", random_key)
    # print("Random iv:", random_iv)
    random_length = randint(5, 10)
    # print("Random length addition:",random_length)
    random_addition = get_random_bytes(random_length)
    # print("Random addition:", random_addition)
    plaintext = random_addition + plaintext + random_addition
    # print("Plaintext:", plaintext)
    choice = randint(1, 2)
    print("Choice:", choice)
    print()

    ciphertext = b""
    cipher_ecb = ecb_module()
    cipher_cbc = cbc_module(random_iv, random_key)

    if choice == 1:
        print("ECB")
        ciphertext = cipher_ecb.ecb_encrypt(plaintext, random_key)

    elif choice == 2:
        print("CBC")
        ciphertext = cipher_cbc.cbc_encrypt(plaintext)

    return ciphertext


def main():

    # Chosen ciphertext attack
    # Create a 3 blocks of 0x00. This way when the oracle is encrypting the plaintext in ECB mode the second and third block will be the same
    oracle = encryption_oracle(bytes([0]*48))
    if oracle[16:32] == oracle[32:48]:
        print("--- Encrypting using ECB ---")
    else:
        print("--- Encrypting using CBC ---")


if __name__ == "__main__":
    main()
