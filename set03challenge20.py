'''

Matasano Crypto Challenges
Set 03 - Challenge 20

BREAK FIXED-NONCE CTR STATISTICALLY

'''
import base64
import struct
from set03challenge18 import ctr_module
from Crypto.Random import get_random_bytes
from set01challenge02 import xor_strings
from set01challenge03 import break_singlebyte_xor
import itertools

target = open('set03challenge20.txt', 'r').readlines()
target_list = [base64.b64decode(line) for line in target]

# Parameters
key = b'YELLOW SUBMARINE'  # get_random_bytes(16)
nonce = struct.pack('Q', 0)  # Expanded to 64bit little endian

cipher = ctr_module(key, nonce)
encrypted_target = [cipher.ctr(item) for item in target_list]


def main():
    # Calculate shortest ciphertext lenght
    min_encrypted_target_length = min(len(i) for i in encrypted_target)

    print("Shortest ciphertext:", min_encrypted_target_length, "bytes")

    # Truncate all ciphertext to minimum length
    encrypted_target_truncated = [
        i[:min_encrypted_target_length] for i in encrypted_target]

    # Check all ciphertext have been truncated to minimum length
    for i in encrypted_target_truncated:
        if len(i) != min_encrypted_target_length:
            raise Exception("*** Ciphertexts haven\'t been truncated ***")

    # Reusing code from Set 01 Challenge 03
    # Transpose the blocks, make a block that is the first byte of every block, and a block that is the second byte etc.
    transposed_target = list(
        itertools.zip_longest(*encrypted_target_truncated, fillvalue=0))
    # Initialize key variable
    keystream = b''
    # Break each single block via single byte xor (Challenge 03)
    for i in transposed_target:
        single_byte = break_singlebyte_xor(i)
        keystream_byte = single_byte['key'].to_bytes(1, byteorder='big')
        keystream += keystream_byte

    print("Recovered key:", keystream)

    recovered_plaintext = [xor_strings(keystream, i)
                           for i in encrypted_target_truncated]

    # First byte of keystream doesn't produce correct plaintext due to statistical limitation
    # The correct first byte is the one that when XOR'd with the first byte of the first cyphertext produces 'I'
    new_byte = b''
    for i in range(256):
        if chr(i ^ encrypted_target_truncated[0][0]) == 'I':
            new_byte = i

    new_first_byte = bytes(chr(new_byte), 'utf-8')
    keystream = new_first_byte + keystream[1:]

    recovered_plaintext = [xor_strings(keystream, i)
                           for i in encrypted_target_truncated]

    # Check decryption is correct
    for i in range(len(recovered_plaintext)):
        if recovered_plaintext[i] != target_list[i][:min_encrypted_target_length]:
            raise Exception("*** FAILED DECRYPTION ***")
        print("Success:", recovered_plaintext[i])


if __name__ == "__main__":
    main()
