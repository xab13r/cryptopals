'''

Matasano Crypto Challenges
Set 02 - Challenge 09

IMPLEMENT PKCS#7 PADDING

'''

input_string = b"YELLOW SUBMARINE"
test_result = b"YELLOW SUBMARINE\x04\x04\x04\x04"


def pkcs7_padding(input_string, block_length):

    padding_length = block_length - len(input_string)
    padding = [padding_length for i in range(padding_length)]

    return input_string + bytes(padding)


def main():
    #result = detect_ecb_mode(ciphertexts)
    #result_index = [ciphertexts.index(i) for i in result]

    if pkcs7_padding(input_string, 20) != test_result:
        raise Exception("Padding function returned the wrong result")
    else:
        print("--- Success ---")
        print(pkcs7_padding(input_string, 20))
        print(test_result)


if __name__ == "__main__":
    main()
