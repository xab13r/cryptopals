'''

Matasano Crypto Challenges
Set 03 - Challenge 17

THE CBC PADDING ORACLE

'''
import base64
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from set02challenge09 import pkcs7_padding
from set01challenge06 import slice_target
from Crypto.Random.random import randint
from set02challenge10 import cbc_module
from set02challenge15 import validate_padding

key = get_random_bytes(16)
iv = get_random_bytes(16)

target = open('set03challenge17.txt', 'r').readlines()
target_list = [base64.b64decode(line) for line in target]

# Function to encrypt a random line from file
def cbc_encrypt_random_line():
    random_line = target_list[randint(0,9)]
    cipher = cbc_module(iv, key)
    ciphertext = cipher.cbc_encrypt(random_line)
    return ciphertext, iv

# CBC Padding Oracle
def cbc_oracle(ciphertext, iv):
    cipher = cbc_module(iv, key)
    plaintext = cipher.cbc_decrypt(ciphertext)
    try:
        validate_padding(plaintext)
        return True
    except:
        return False

# Function to flip byte in offset'th position to specific value
def set_byte(array, offset, value):
    array = array[0:offset] + value.to_bytes(1, byteorder='big') + array[offset+1:len(array)]
    return array

# Using specific IV, the goal is to 'guess' the value of the byte in indexth position - counting backwards (0 is last byte, 1 is second to last, etc.)
# Known plaintext will store guessed bytes value
def generate_iv(input_iv, index, guess, knownPlaintext):
    # Target 0000000000 | guess | known_plaintext
    #prefix = 
    #suffix = 

    expanded_plaintext = b"\x00" * (len(input_iv) - len(knownPlaintext) - 1) + guess.to_bytes(1, byteorder='big')  + knownPlaintext;
    
    # IV XOR Expanded Plaintext
    iv_xor_plaintext = b''
    for i in range(len(input_iv)):
        iv_xor_plaintext += (input_iv[i] ^ expanded_plaintext[i]).to_bytes(1, byteorder='big')
    
    # (IV XOR Expanded Plaintext) XOR Padding 
    padding = b"\x00" * (len(input_iv) - index - 1) + ((index+1).to_bytes(1, byteorder='big') * (index+i))
    result = b''
    for i in range(len(iv_xor_plaintext)):
        result += (iv_xor_plaintext[i] ^ padding[i]).to_bytes(1, byteorder='big');
    return result




# Function to recover plaintext blocks
def recover_block_plaintext(block, input_iv):
    recovered_plaintext = b""
    # For each byte in the block
    for byte_index in range(len(block)):
        # Guess byte value cycling through all 256 possible values
        for byte_value in range(256):
            # Generate specific IV for the value
            current_iv = generate_iv(input_iv, byte_index, byte_value, recovered_plaintext)

            # Check padding
            if cbc_oracle(block, current_iv):
                if byte_index == 0:
                    current_iv = set_byte(current_iv, len(current_iv)-2, current_iv[len(current_iv) - 2] ^ 0xff)
                    if cbc_oracle(block, current_iv) == False:
                        continue
                recovered_plaintext = byte_value.to_bytes(1, byteorder='big') + recovered_plaintext
                # Move to next byte
                break
            if byte_value == 255:
                print("*** ERROR ***")

    return recovered_plaintext


def decryption_via_oracle():
    encryption = cbc_encrypt_random_line()
    target_ciphertext = encryption[0]
    target_iv = encryption[1]
    target_blocks = slice_target(target_ciphertext, 16)
    plaintext = b""
    for i in range(len(target_blocks)):
        plaintext += recover_block_plaintext(target_blocks[i], target_iv)
        target_iv = target_blocks[i]
    return plaintext   

def main():
    plaintext = decryption_via_oracle()
    padding = plaintext[-1]
    print("Plaintext:", plaintext[:-padding])


if __name__ == "__main__":
    main()
