'''

Matasano Crypto Challenges
Set 01 - Challenge 07

AES IN ECB MODE

'''

import base64
from Crypto.Cipher import AES

target = base64.b64decode(open('set01challenge07.txt', 'r').read())
key = b'YELLOW SUBMARINE'

# Initialize Cipher
cipher = AES.new(key, AES.MODE_ECB)

# Decrypt
plaintext = cipher.decrypt(target)


def main():

    print("--- Decoded Plaintext ---")
    print(plaintext)


if __name__ == "__main__":
    main()
