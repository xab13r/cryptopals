'''

Matasano Crypto Challenges
Set 02 - Challenge 10

IMPLEMENT CBC MODE

'''

import base64
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from set02challenge09 import pkcs7_padding
from set01challenge06 import slice_target

target = base64.b64decode(open('set02challenge10.txt', 'r').read())
example = b"this is a test to be encrypted and its note the right length"
key = b"YELLOW SUBMARINE"
iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


class cbc_module():

    def __init__(self, iv, key):
        self.iv = iv
        self.key = key
        self.cipher = AES.new(key, AES.MODE_ECB)
        self.keysize = 16

    def cbc_encrypt(self, plaintext):
        ciphertext = b""
        plaintext = slice_target(plaintext, self.keysize)
        previous_block = self.iv

        if len(plaintext[-1]) != self.keysize:
            plaintext[-1] = pkcs7_padding(plaintext[-1], self.keysize)

        cipherblocks = [b"" for i in plaintext]

        for i in range(len(plaintext)):
            cipherblocks[i] = self.cipher.encrypt(
                strxor(plaintext[i], previous_block))
            previous_block = cipherblocks[i]

        ciphertext = b""
        for i in cipherblocks:
            ciphertext += i

        return ciphertext

    def cbc_decrypt(self, ciphertext):
        plaintext = b""
        ciphertext = slice_target(ciphertext, self.keysize)
        previous_block = self.iv
        plainblocks = [b"" for i in ciphertext]

        for i in range(len(ciphertext)):
            plainblocks[i] = strxor(self.cipher.decrypt(
                ciphertext[i]), previous_block)
            previous_block = ciphertext[i]

        for i in plainblocks:
            plaintext += i

        return plaintext


def main():
    cipher = cbc_module(iv, key)
    decrypted = cipher.cbc_decrypt(target)
    print(decrypted)
    print()
    encrypted = cipher.cbc_encrypt(decrypted)

    if encrypted != target:
        raise Exception("Error - File value doesn't match source")
    else:
        print("--- Success ---")


if __name__ == "__main__":
    main()
