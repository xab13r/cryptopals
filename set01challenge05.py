'''

Matasano Crypto Challenges
Set 01 - Challenge 05

IMPLEMENT REPEATING-KEY XOR

'''

import binascii
from set01challenge02 import xor_strings

plaintext = b'''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''

key = b'ICE'

expected_result = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'


def repeating_key_xor(input_string, key):
    # xor_string function accepts hex encoded strings as inputs
    hex_input_string = binascii.hexlify(input_string)
    hex_key = binascii.hexlify(key)
    xor_string = xor_strings(hex_input_string, hex_key)
    return xor_string


def main():

    print(binascii.hexlify(repeating_key_xor(plaintext, key)))
#    print(binascii.unhexlify(expected_result))
#    print(binascii.unhexlify(repeating_key_xor(plaintext, key)))

    # Check result against expected
    if repeating_key_xor(plaintext, key) != binascii.unhexlify(expected_result):
        raise Exception("Error - Strings don\'t match")
    else:
        print("--- Success ---")


if __name__ == "__main__":
    main()
