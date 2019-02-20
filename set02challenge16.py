'''

Matasano Crypto Challenges
Set 02 - Challenge 16

CBC BITFLIPPING ATTACKS

'''

from os import urandom as get_random_bytes
import binascii
from set02challenge10 import cbc_module
from set01challenge02 import xor_strings
from set02challenge14 import slice_blocks

key = get_random_bytes(16)
iv = get_random_bytes(16)
prefix = b"comment1=cooking%20MCs;userdata="
suffix = b";comment2=%20like%20a%20pound%20of%20bacon"


def encrypt_parameters(input_string):

    # Quote out '=' and ';' from input string and convert to bytes
    input_string = bytes(input_string.replace(
        ';', '%3B').replace('=', '%3D'), 'utf-8')

    parameters_string = prefix + input_string + suffix

    cipher = cbc_module(iv, key)
    ciphertext = cipher.cbc_encrypt(parameters_string)
    return ciphertext


def decrypt_parameters_and_check_admin(input_string):
    cipher = cbc_module(iv, key)
    plaintext = cipher.cbc_decrypt(input_string)
    if b";admin=true;" in plaintext:
        print("Plaintext:", plaintext)
        return True
    else:
        return False


def generate_admin_profile():
    # Calculate length of prefix and force encryption to a new block
    bytes_to_new_block = 'A' * (16 - (len(prefix) % 16))
    # Identify ciphertext used as IV for the new block

    index_of_iv_to_use = ((len(prefix) + len(bytes_to_new_block)) // 16) - 1
    # Add a known block
    known_block = bytes_to_new_block + ('X' * 16)
    # Encrypt chosen plaintext
    ciphertext = encrypt_parameters(known_block)
    # Slice ciphertext
    ciphertext_blocks = slice_blocks(ciphertext, 16)
    # Isolate IV block
    iv_to_use = ciphertext_blocks[index_of_iv_to_use]
    # XOR in IV with target value
    hex_iv = iv_to_use
    hex_known = b'X'*16
    hex_target = b";admin=true;\x04\x04\x04\x04"
    new_hex_iv = xor_strings(hex_iv,
        xor_strings(hex_target, hex_known))
    # Inject block into ciphertext
    ciphertext_blocks[index_of_iv_to_use] = new_hex_iv
    # Re-generate ciphertext from block
    new_ciphertext = b''
    for i in ciphertext_blocks:
        new_ciphertext += i
    return new_ciphertext


def main():
    # Verify '=', ',', and ';' are sanitized on input
    if decrypt_parameters_and_check_admin(encrypt_parameters(";admin=true;")):
        raise Exception("--- Nice try ---")
    # Generate chosen ciphertext
    ciphertext = generate_admin_profile()
    # Verify chosen ciphertext inject admin profile
    if decrypt_parameters_and_check_admin(ciphertext):
        print("--- Success ---")
    else:
        raise Exception("*** Failed ***")


if __name__ == "__main__":
    main()
