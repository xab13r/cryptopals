'''

Matasano Crypto Challenges
Set 01 - Challenge 02

FIXED XOR

'''

import binascii

string1 = "1c0111001f010100061a024b53535009181c"
string2 = "686974207468652062756c6c277320657965"
expected_result = "746865206b696420646f6e277420706c6179"


def xor_strings(string1, string2):

    # Make strings the same length
    if len(string1) > len(string2):
        string2 *= int(len(string1)/len(string2)+1)
        string2 = string2[:len(string1)]

    if len(string1) < len(string2):
        string1 *= int(len(string2)/len(string1)+1)
        string1 = string1[:len(string2)]

    bytes_string1 = binascii.unhexlify(string1)  # Convert to type bytes
    bytes_string2 = binascii.unhexlify(string2)  # Convert to type bytes

    xor_string = b''
    for i in range(len(bytes_string1)):
        xor_string += bytes([bytes_string1[i] ^ bytes_string2[i]])

    return xor_string # Value returned is type bytes


def main():
    
    print(string1)
    print(string2)
    
    print(binascii.hexlify(xor_strings(string1, string2)))
    
    if xor_strings(string1, string2) != binascii.unhexlify(expected_result):
        raise Exception("Error - Strings don\'t match")
    else:
        print("--- Success ---")


if __name__ == "__main__":
    main()
