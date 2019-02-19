'''

Matasano Crypto Challenges
Set 01 - Challenge 02

FIXED XOR

'''

import binascii


def xor_strings(string1, string2):

    # Check strings' length
    if len(string1) != len(string2):
        raise Exception("Only strings of same length can be XOR'd")

    if type(string1) is not bytes and type(string2) is not bytes:
        # Convert to type bytes
        string1 = binascii.unhexlify(string1)
        string2 = binascii.unhexlify(string2)

    xor_len = len(string1)
    xor_string = b''  # Initialize output

    for i in range(xor_len):
        xor_string += bytes([string1[i] ^ string2[i]])

    return xor_string  # Value returned is type bytes


def main():

    string1 = "1c0111001f010100061a024b53535009181c"
    string2 = "686974207468652062756c6c277320657965"
    expected_result = "746865206b696420646f6e277420706c6179"

    if xor_strings(string1, string2) != binascii.unhexlify(expected_result):
        raise Exception("Error - Strings don\'t match")
    else:
        print("--- Success ---")

    if xor_strings(binascii.unhexlify(string1), binascii.unhexlify(string2)) != binascii.unhexlify(expected_result):
        raise Exception("Error - Strings don\'t match")
    else:
        print("--- Success ---")


if __name__ == "__main__":
    main()
