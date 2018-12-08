'''

Matasano Crypto Challenges
Set 01 - Challenge 04

DETECT SINGLE-CHARACTER XOR

'''

import binascii
from set01challenge01 import hex_to_bytes
from set01challenge03 import break_singlebyte_xor, english_score

expected_result = 'Now that the party is jumping'

# Open file and create a list of ciphertext in type byte
ciphertexts = [hex_to_bytes(i) for i in open(
    "set01challenge04.txt").read().splitlines()]


def main():

    # Brute force all ciphertexts and generate a list of possible results
    possible_results = [break_singlebyte_xor(i) for i in ciphertexts]

    # Run all plaintexts through english_score and save the score
    scored_results = [english_score(i.get('plaintext'))
                      for i in possible_results]

    # Get index of best score
    best_result_index = scored_results.index(max(scored_results))

    solution = possible_results[best_result_index]
    # Print result in a legible way

    print(
        solution['plaintext'].decode().rstrip(),
        "\nScore:", solution['score'],
        "\nKey:", chr(solution['key']))

    # Check result against expected
    if solution['plaintext'].decode().rstrip() != expected_result:
        raise Exception("Error - Strings don\'t match")
    else:
        print("--- Success ---")


if __name__ == "__main__":
    main()
