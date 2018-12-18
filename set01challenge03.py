'''

Matasano Crypto Challenges
Set 01 - Challenge 03

SINGLE-BYTE XOR

'''

import codecs
import base64
from set01challenge01 import hex_to_bytes

# http://www.data-compression.com/english.html
character_freq = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835,
    'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610, 'h': 0.0492888,
    'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490,
    'm': 0.0202124, 'n': 0.0564513, 'o': 0.0596302, 'p': 0.0137645,
    'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357,
    'u': 0.0225134, 'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692,
    'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}

ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
expected_result = b'Cooking MC\'s like a pound of bacon'


def english_score(bytes_input):  # Input needs to be type bytes

    score = 0

    for byte in bytes_input:
        score += character_freq.get(chr(byte).lower(), 0)

    return score


def single_xor(bytes_ciphertext, single_key):  # Input needs to be type bytes

    output = b''

    for char in bytes_ciphertext:
        output += bytes([char ^ single_key])

    return output


def break_singlebyte_xor(bytes_input):
    possible_results = []

    # Try all the key
    for possible_key in range(256):
        possible_plaintext = single_xor(bytes_input, possible_key)
        possible_key_score = english_score(possible_plaintext)

        # Generate result for each key
        result = {
            'key': possible_key,
            'score': possible_key_score,
            'plaintext': possible_plaintext
        }

        # Append result to dictionary
        possible_results.append(result)

    # Return the result with the highest English score
    return sorted(possible_results, key=lambda c: c['score'], reverse=True)[0]


def main():

    # Convert ciphertext to bytes
    bytes_ciphertext = hex_to_bytes(ciphertext)

    # Generate dictionary of possible plaintexts and return highest score
    highest_score_plaintext = break_singlebyte_xor(bytes_ciphertext)

    # Print result in a legible way
    print(
        highest_score_plaintext['plaintext'].decode(),
        "\nScore:", highest_score_plaintext['score'],
        "\nKey:", chr(highest_score_plaintext['key']))

    # Check result against expected
    if highest_score_plaintext['plaintext'] != expected_result:
        raise Exception("Error - Strings don\'t match")
    else:
        print("--- Success ---")


if __name__ == "__main__":
    main()
