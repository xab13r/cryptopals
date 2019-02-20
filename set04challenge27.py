'''

Matasano Crypto Challenges
Set 04 - Challenge 27

RECOVER THE KEY FROM CBC WITH IV=KEY

'''

from Crypto.Random import get_random_bytes
from set02challenge10 import cbc_module
from set01challenge02 import xor_strings

key = get_random_bytes(16)
iv = key


def encrypt_parameters(input_string):
    prefix = b"comment1=cooking%20MCs;userdata="
    suffix = b";comment2=%20like%20a%20pound%20of%20bacon"

    # Quote out '=' and ';' from input string and convert to bytes
    input_string = bytes(input_string.replace(
        ';', '%3B').replace('=', '%3D'), 'utf-8')

    parameters_string = prefix + input_string + suffix

    cipher = cbc_module(iv, key)
    ciphertext = cipher.cbc_encrypt(input_string)

    return ciphertext


def decrypt_and_check_ascii(input_string):
    cipher = cbc_module(iv, key)
    plaintext = cipher.cbc_decrypt(input_string)
    for i in plaintext:
        if int(i) > 127:
            print(
                '*** ERROR: High-ASCII values found ***\n{0}'.format(plaintext))
            return plaintext

    return True


def main():
    three_block_message = '0' * 48  # At least 3 blocks long
    ciphertext = encrypt_parameters(three_block_message)
    chosen_ciphertext = ciphertext[:16] + bytes([0]) * 16 + ciphertext[:16]
    output = decrypt_and_check_ascii(chosen_ciphertext)
    recovered_key = xor_strings(output[:16], output[32:])

    if recovered_key == key:
        print("\nExpected key:", key)
        print("Recovered key:", recovered_key)
        print("--- Success ---")
    else:
        raise Exception("*** FAILED ***")


if __name__ == "__main__":
    main()
