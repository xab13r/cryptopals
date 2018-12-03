'''
Matasano Crypto Challenges
Set 01 - Challenge 02

FIXED XOR

'''


import codecs
import base64
from set01challenge01 import hex_to_bytes

string1 = "1c0111001f010100061a024b53535009181c"
string2 = "686974207468652062756c6c277320657965"
expected_result = "746865206b696420646f6e277420706c6179"


def xor_strings(string1, string2):
    int_string1 = int(string1, 16)  # XOR operation on INT
    int_string2 = int(string2, 16)  # XOR operation on INT

    if len(string1) != len(string2):
        raise Exception("Error - Strings length doesn\' match")

    else:
        xor_string = int_string1 ^ int_string2

    return hex(xor_string)[2:]  # Remove '0x' prefix from hex encoding


def main():
    print(string1)
    print(string2)
    print(expected_result)

    if xor_strings(string1, string2) != expected_result:
        raise Exception("Error - Strings don\'t match")
    else:
        print("--- Success ---")


if __name__ == "__main__":
    main()
