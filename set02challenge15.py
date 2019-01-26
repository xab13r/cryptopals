'''

Matasano Crypto Challenges
Set 02 - Challenge 15

PKCS#7 PADDING VALIDATION

'''

from Crypto.Random import get_random_bytes
from set02challenge11 import ecb_module

target_string = b"ICE ICE BABY\x04\x04\x04\x04"


def validate_padding(bytes_string):

    padding_value = bytes_string[-1]
    expected_padding = bytes(padding_value * [padding_value])
    actual_padding = bytes_string[-padding_value:]

    if padding_value == 0:
        raise Exception("--- Bad Padding ---")

    elif actual_padding != expected_padding:
        raise Exception("--- Bad Padding ---")
    
    elif actual_padding == expected_padding:
        stripped_string = bytes_string[:-padding_value]
        return stripped_string


def main():
    
    print("Testing target string:", target_string)
    if validate_padding(target_string):
        print("--- Valid Padding ---")
        print(validate_padding(target_string))


if __name__ == "__main__":
    main()
