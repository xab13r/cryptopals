'''

Matasano Crypto Challenges
Set 01 - Challenge 06

BREAK REPEATING-KEY XOR

'''

import base64
import itertools
from set01challenge03 import break_singlebyte_xor
from set01challenge05 import repeating_key_xor

string1 = 'this is a test'
string2 = 'wokka wokka!!!'
expected_distance = 37
max_keysize = 40

target = base64.b64decode(open('set01challenge06.txt', 'r').read())


def hamming_distance(string1, string2):
    # Check strings length matches
    if len(string1) != len(string2):
        raise Exception("Strings length doesn't match")

    # Convert strings to bytes for processing
    if (type(string1) or type(string2)) != bytes:
        string1 = bytes(string1, 'utf-8')
        string2 = bytes(string2, 'utf-8')

    # Initialize variable
    hamming_distance = 0
    for i, j in zip(string1, string2):
        # XOR each couple of characters and count differing bits
        hamming_distance += bin(i ^ j).count('1')
    return hamming_distance


def slice_target(ciphertext, keysize):
    # Break the ciphertext into blocks of keysize length
    return [ciphertext[i:i+keysize] for i in range(0, len(ciphertext), keysize)]


def guess_keysize(ciphertext, keysize):
    # Break the ciphertext into blocks of keysize length
    sliced_target = slice_target(ciphertext, keysize)
    # Take 4 keysize blocks
    sample_target = sliced_target[0:4]
    # Generate a list of possible combinations of the 4 blocks
    combinations = list(itertools.combinations(sample_target, 2))
    # Generate a list with normalized hamming distance for each pair combination
    results = [hamming_distance(p[0], p[1]) / keysize for p in combinations]
    # Calculate hamming distance average for the sample
    averaged_result = sum(results) / len(results)
    return averaged_result


def best_keysize(ciphertext, max_keysize):
    # Generate list of tuples with keylength and hamming distance average
    averaged_distances = [(i, guess_keysize(target, i))
                          for i in range(2, max_keysize + 1)]
    # Sort list by smallest average hamming distance
    averaged_distances.sort(key=lambda distance: distance[1])
    # Return keylength for smallest average hamming distance
    return averaged_distances[0][0]


def break_repeating_key_xor(ciphertext, keysize):
    # Break the ciphertext into blocks of keysize length
    sliced_target = slice_target(ciphertext, keysize)
    # Transpose the blocks, make a block that is the first byte of every block, and a block that is the second byte etc.
    transposed_target = list(
        itertools.zip_longest(*sliced_target, fillvalue=0))
    # Initialize key variable
    key = b''
    # Break each single block via single byte xor (Challenge 03)
    for i in transposed_target:
        single_byte = break_singlebyte_xor(i)
        key += bytes(chr(single_byte['key']), 'utf-8')
    return key


def break_repeating_key(ciphertext, max_keysize):
    print("Max key length:", max_keysize)
    print("Calculating best hamming distance average...")
    best_keylength = best_keysize(ciphertext, max_keysize)
    print("Best keysize:", best_keylength)
    recovered_key = break_repeating_key_xor(ciphertext, best_keylength)
    print("Recovered key:", recovered_key)
    return recovered_key


def main():

    print("Expected Hamming Distance:", expected_distance)
    print("Computed Hamming Distance:", hamming_distance(string1, string2))
    if expected_distance == hamming_distance(string1, string2):
        print("--- Hamming Distance matches ---")
        print("")
    else:
        raise Exception("Error - Hamming Distance doesn\'t match")

    recovered_key = break_repeating_key(target, 40)

    plaintext = repeating_key_xor(target, recovered_key)

    print("")
    print("--- Decoded Plaintext ---")
    print(plaintext)


if __name__ == "__main__":
    main()
