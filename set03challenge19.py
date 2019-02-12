'''

Matasano Crypto Challenges
Set 03 - Challenge 19

BREAK FIXED-NONCE CTR MODE USING SUBSTITUTIONS

'''
import base64
import struct
from set03challenge18 import ctr_module
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor


target = open('set03challenge19.txt', 'r').readlines()
target_list = [base64.b64decode(line) for line in target]

# Parameters
key = get_random_bytes(16)
nonce = struct.pack('Q', 0)  # Expanded to 64bit little endian

cipher = ctr_module(key, nonce)
encrypted_target = [cipher.ctr(item) for item in target_list]


def single_character_decryption(encrypted_target, i):
    # For each of the 256 possible guess-values:
    for guess in range(256):
        # Generate a list of all the 256 values of guess
        # XOR'd against the value at index i of each ciphertext
        decrypted = [encrypted_item[i] ^
                     guess for encrypted_item in encrypted_target]
        # If all the XOR'd values are characters in the list provided,
        # Then return the value of guess
        if all([chr(x) in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ,' for x in decrypted]):
            return guess


def prepare_key(keystream):
    # Generate a bytes-type object from keystream
    # generated using single_character_decryption
    key = b''
    for i in keystream:
        key += bytes([i])
    return key


def expand_key(key, ciphertext, guess):
    # Given a guess, XOR it against the ciphertext
    expansion = bytes([guess[i] ^ ciphertext[len(key) + i]
                       for i in range(len(guess))])
    # Add the expansion to the key
    return key + expansion


def decrypt_target(guessed_key, encrypted_target):
    key_length = len(guessed_key)
    # Account for the length value of both the ciphertext and the key
    # Short the key to the length of the ciphertext and viceversa
    # The decryption process is a simple XOR
    decrypted_target = [strxor(guessed_key[:len(i)], i[:key_length])
                        for i in encrypted_target]
    return decrypted_target


def main():
    # Manual iterations of single_character_decryption show that we get result
    # for the first 10 bytes of the keystream
    keystream = [single_character_decryption(
        encrypted_target, i) for i in range(10)]

    # Generate key from keystream
    guessed_key = prepare_key(keystream)

    # Guess Work, FUN!
    guessed_key = expand_key(guessed_key, encrypted_target[1], b'h ')
    guessed_key = expand_key(guessed_key, encrypted_target[3], b'entury ')
    guessed_key = expand_key(guessed_key, encrypted_target[5], b'ss ')
    guessed_key = expand_key(guessed_key, encrypted_target[3], b'se')
    guessed_key = expand_key(guessed_key, encrypted_target[5], b'rds')
    guessed_key = expand_key(guessed_key, encrypted_target[0], b' ')
    guessed_key = expand_key(guessed_key, encrypted_target[8], b'e')
    guessed_key = expand_key(guessed_key, encrypted_target[35], b't')
    guessed_key = expand_key(guessed_key, encrypted_target[4], b'e ')
    guessed_key = expand_key(guessed_key, encrypted_target[27], b'd')
    guessed_key = expand_key(guessed_key, encrypted_target[4], b'ead')
    guessed_key = expand_key(guessed_key, encrypted_target[37], b'n,')

    decrypted_target = decrypt_target(guessed_key, encrypted_target)

    '''
    # Printing Instruction for Manual Decryption
    print("Next guess:")
    for i in range(len(decrypted_target)):
        if len(encrypted_target[i]) > len(guessed_key):
            print(i, decrypted_target[i], str(len(guessed_key)) + "/" + str(len(encrypted_target[i])) )
            
    print(decrypted_target)
    '''

    for i in range(len(decrypted_target)):
        # Added a lower case transformation to account for any variances in the displayed text
        if decrypted_target[i].lower() != target_list[i].lower():
            raise Exception("*** FAILED DECRYPTION ***")
        print("Success:", decrypted_target[i])


if __name__ == "__main__":
    main()
