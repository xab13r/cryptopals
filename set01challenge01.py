'''
Matasano Crypto Challenges
Set 01 - Challenge 01

CONVERT HEX TO BASE64

'''

import codecs
import base64

input_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
expected_result = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"


def hex_to_bytes(hex_string):
    bytes_string = codecs.decode(
        hex_string, encoding='hex')  # Convert string to bytes
    return(bytes_string)


def bytes_to_base64(bytes_string):
    # Encode to Base64, type is still bytes
    base64_string = base64.b64encode(bytes_string)
    return base64_string


def hex_to_base64(hex_string):
    # ASCII decoding used to print compare result with expected result
    return bytes_to_base64(hex_to_bytes(hex_string)).decode('ascii')


def main():
    print(hex_to_base64(input_string))
    print(expected_result)

    if hex_to_base64(input_string) != expected_result:
        raise Exception("Error - Strings don\'t match")
    else:
        print("--- Success ---")


if __name__ == "__main__":
    main()
