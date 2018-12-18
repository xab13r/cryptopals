'''

Matasano Crypto Challenges
Set 01 - Challenge 08

DETECT AES IN ECB MODE

'''

#from Crypto.Cipher import AES
from set01challenge01 import hex_to_bytes
from set01challenge06 import slice_target
import itertools

# Open file and create a list of ciphertext in type byte
ciphertexts = [hex_to_bytes(i) for i in open(
    "set01challenge08.txt").read().splitlines()]


def detect_ecb_mode(ciphertexts):
    result = []
    # Iterate through all ciphertexts
    for ciphertext in ciphertexts:
        # Break ciphertext in blocks of 16 bytes
        target = slice_target(ciphertext, 16)
        # Total number of block in a given cipher is the length of the list
        number_of_blocks = len(target)
        # Initialize a dictionary to keep tracks of repeating blocks
        distinct_blocks = {}
        # Iterate through all blocks
        for i in target:
            # Assign value 1 to each distinct blocks
            distinct_blocks[i] = 1
        # Total number of distinct blocks is the length of the dictionary
        number_of_distinct_blocks = len(distinct_blocks)

        # Look for only ciphertexts with repeating blocks
        if number_of_distinct_blocks < number_of_blocks:
            # Append result to the result list
            result.append(ciphertext)
    return result


def main():
    result = detect_ecb_mode(ciphertexts)
    result_index = [ciphertexts.index(i) for i in result]

    if len(result) == len(result_index):
        for i in range(len(result)):
            if result[i] == ciphertexts[result_index[i]]:
                print("Detected ECB Mode for ciphertext #",
                      ciphertexts.index(result[i]))
                print("Ciphertext:", ciphertexts[i])


if __name__ == "__main__":
    main()
