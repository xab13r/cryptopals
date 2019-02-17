'''

Matasano Crypto Challenges
Set 04 - Challenge 25

BREAK "RANDOM ACCESS READ/WRITE" AES CTR

'''

from Crypto.Cipher import AES
import base64
from set03challenge18 import ctr_module
from Crypto.Util.strxor import strxor
import struct
import sys
import time


def edit(ciphertext, offset, new_text):
    key = b'YELLOW SUBMARINE'
    nonce = struct.pack('Q', 0)
    cipher = ctr_module(key, nonce)  # Initialize cipher

    # Because of the keystream nature of CTR we can encrypt a specific character at position 'offset' fairly easily
    encrypted_new_text = cipher.ctr(bytes([0]) * offset + new_text)

    # Then, slice the original ciphertext and inject the new text encrypted
    prefix = ciphertext[:offset]
    injection = encrypted_new_text[offset:]
    suffix = ciphertext[offset + len(encrypted_new_text):]
    chosen_ciphertext = prefix + injection + suffix
    return chosen_ciphertext


def break_rw_ctr(ciphertext):
    # Cretae a list with all possible ASCII characters
    possible_characters = [chr(i) for i in range(256)]
    # Initialize output
    output = b''

    # Iterate for each position in the ciphertext
    for i in range(len(ciphertext)):
        for item in possible_characters:
            # Generate a new ciphertext for each ASCII character in each position along the ciphertext
            chosen_ciphertext = edit(ciphertext, i, bytes(item, 'utf-8'))

            # If the encryption of the chosen ciphertext matches the original ciphertext, then that's the plaintext at that position
            if chosen_ciphertext[i] == ciphertext[i]:
                print("Breaking location", i, "of", len(ciphertext))
                output += bytes(item, 'utf-8')

    return output


def main():

    # Set 01 - Challenge 07
    target = base64.b64decode(open('set04challenge25.txt', 'r').read())
    key = b'YELLOW SUBMARINE'
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(target)

    # Proceeding with current challenge
    nonce = struct.pack('Q', 0)
    cipher = ctr_module(b'YELLOW SUBMARINE', struct.pack('Q', 0))
    ciphertext = cipher.ctr(plaintext)

    recovered_plaintext = break_rw_ctr(ciphertext)

    if recovered_plaintext != plaintext:
        print("*** FAILED ***")

    print("--- Success ---")


if __name__ == "__main__":
    main()
