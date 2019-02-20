'''

Matasano Crypto Challenges
Set 03 - Challenge 18

IMPLEMENT CTR

'''
import base64
import struct
from Crypto.Cipher import AES
from set01challenge02 import xor_strings
from set01challenge06 import slice_target

target = base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')

# Parameters
key = b'YELLOW SUBMARINE'
nonce = struct.pack('Q', 0) # Expanded to 64bit little endian

class ctr_module():

    def __init__(self, key, nonce):
        # Create cipher instance
        self.cipher = AES.new(key, AES.MODE_ECB)
        self.key = key
        self.nonce = nonce
        self.keysize = 16

    # CTR Method
    def ctr(self, target):
        # Slice plaintext into blocks
        target_blocks = slice_target(target, self.keysize)
        # Initialize plaintext variable
        plaintext = b''
        # Slice target into blocks
        blocks = slice_target(target, 16)

        # Iterate on each block
        for i in range(len(blocks)):
            # Expand counter to 64 bit little endian
            block_counter = struct.pack('<Q', i)
            # Generate block stream
            # format=64 bit unsigned little endian nonce, 64 bit little endian block count (byte count / 16)
            block_stream = self.nonce + block_counter
            # Generate keystream
            ciphertext = self.cipher.encrypt(block_stream)
            # Generate plaintext
            plaintext += xor_strings(blocks[i], ciphertext[:len(blocks[i])])

        return plaintext



def main():
    cipher = ctr_module(key, nonce)
    print(cipher.ctr(target))

if __name__ == "__main__":
    main()
