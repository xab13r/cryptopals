'''

Matasano Crypto Challenges
Set 04 - Challenge 26

CTR BITFLIPPING

'''

from set03challenge18 import ctr_module
from Crypto.Util.strxor import strxor
import struct

#key = get_random_bytes(16)
#nonce = get_random_bytes(8)
key = b'YELLOW SUBMARINE'
nonce = struct.pack('Q', 0)
prefix = b"comment1=cooking%20MCs;userdata="
suffix = b";comment2=%20like%20a%20pound%20of%20bacon"

def encrypt_parameters(input_string):

    # Quote out '=' and ';' from input string and convert to bytes
    input_string = bytes(input_string.replace(
        ';', '%3B').replace('=', '%3D'), 'utf-8')

    parameters_string = prefix + input_string + suffix

    cipher = ctr_module(key, nonce)
    ciphertext = cipher.ctr(parameters_string)
    return ciphertext

def decrypt_parameters_and_check_admin(input_string):
    cipher = ctr_module(key, nonce)
    plaintext = cipher.ctr(input_string)
    if b";admin=true;" in plaintext:
        return True
    else:
        return False

def main():
    # Verify '=', ',', and ';' are sanitized on input
    if decrypt_parameters_and_check_admin(encrypt_parameters(";admin=true;")):
        raise Exception("--- Nice try ---")
    # Generate chosen ciphertext
    ciphertext = encrypt_parameters('\x00admin\x00true\x00')
    target = list(ciphertext)
    target[32] = ciphertext[32] ^ 59
    target[38] = ciphertext[38] ^ 61
    target[43] = ciphertext[43] ^ 59
    chosen_ciphertext = b''
    for i in target:
        chosen_ciphertext += i.to_bytes(1, byteorder='big')
    # Verify chosen ciphertext inject admin profile
    if decrypt_parameters_and_check_admin(chosen_ciphertext):
        print("--- Success ---")
    else:
        raise Exception("*** Failed ***")
    

if __name__ == "__main__":
    main()
