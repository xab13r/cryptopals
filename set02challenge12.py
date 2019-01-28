'''

Matasano Crypto Challenges
Set 02 - Challenge 12

BYTE-AT-A-TIME ECB DECRYPTION (SIMPLE)

'''

import base64
from Crypto.Random import get_random_bytes
from set02challenge11 import ecb_module


def encryption_oracle(plaintext):
    global random_key
    random_key = get_random_bytes(16)

    encoded_suffix = base64.b64decode(
        'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

    expanded_plaintext = plaintext + encoded_suffix

    cipher_ecb = ecb_module()
    ciphertext = cipher_ecb.ecb_encrypt(expanded_plaintext, random_key)

    return ciphertext


def determine_ecb(blocksize):
    plaintext = bytes([0]*blocksize*2)
    ciphertext = encryption_oracle(plaintext)
    if ciphertext[:blocksize] == ciphertext[blocksize:2*blocksize]:
        print("Encryption Oracle is using ECB")
    else:
        raise Exception("--- Encryption Oracle is not using ECB ---")


def find_blocksize(encryption_oracle):
    # An empty string will force the oracle to apply padding to the encoded suffix to fill an unknown number of blocks with a length that can be defined as:
    length_of_null_string = len(encryption_oracle(b''))
    i = 1
    # Let's feed one byte at-a-time to the encryption oracle, until a new block is created. The difference between the ciphertext generated by a null string and the one that will force the creation of a new block will yield the blocksize
    while True:
        plaintext = bytes([0] * i)
        ciphertext = encryption_oracle(plaintext)
        if len(ciphertext) != length_of_null_string:
            return len(ciphertext) - length_of_null_string
        i += 1


def find_next_byte(blocksize):
    # Initialize variable for known bytes
    known_bytes = b''

    # This is gonna be a loop
    while True:
        # Create a string short of the length of known bytes (starting with one)
        string_short = bytes(
            [0]*(blocksize - (len(known_bytes) % blocksize) - 1))
        # Initialize dictionary for storing encrypted strings
        one_byte_dictionary = {}
        # Loop through all the 256 characters
        for i in range(256):
            # Encrypt shortened string | known bytes | character
            ciphertext = encryption_oracle(
                string_short + known_bytes + bytes([i]))
            # Get first block of the encrypted string and add to the dictionary
            one_byte_dictionary[ciphertext[0:len(
                string_short) + len(known_bytes) + 1]] = i
        # Encrypt the shortened string
        ciphertext_short = encryption_oracle(string_short)
        # Get first block on the encrypted shortened string
        ciphertext_sliced = ciphertext_short[0: len(
            string_short) + len(known_bytes) + 1]
        # Check for a match in the dictionary; if found, add the character to the known_bytes string
        if ciphertext_sliced in one_byte_dictionary:
            known_bytes += bytes([one_byte_dictionary[ciphertext_sliced]])
        # Break the loop as soon as no match is found inside the dictionary
        else:
            return known_bytes

    return known_bytes


def main():
    blocksize = find_blocksize(encryption_oracle)
    print("Found blocksize:", blocksize)
    determine_ecb(blocksize)

    known_bytes = find_next_byte(blocksize)

    print("Decrypted:", known_bytes)


if __name__ == "__main__":
    main()
