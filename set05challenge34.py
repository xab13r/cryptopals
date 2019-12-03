'''

Matasano Crypto Challenges
Set 05 - Challenge 34

IMPLEMENT A MITM KEY-FIXING ATTACK ON DIFFIE-HELLMAN WITH PARAMETER INJECTION

'''

from random import randint
import hashlib
from os import urandom as get_random_bytes
from set02challenge10 import cbc_module

p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16)
g = 2
secret_message = b"This is a secret message"


class DH():

    # Generate private key
    def __init__(self):
        self.private_key = randint(0, 1024) % 37

    # Generate public key
    def generate_public_key(self, p, g):
        public_key = pow(g, self.private_key, p)
        return public_key

    def generate_encryption_key(self, public_key, p):
        # Generate shared_secret based on other party's public_key
        shared_secret = pow(public_key, self.private_key, p)
        shared_secret = str(shared_secret).encode('utf-8')
        encryption_key = hashlib.sha1(
            shared_secret).hexdigest().encode('utf-8')[0:16]
        return encryption_key

    def encrypt(self, iv, key, plaintext):
        cipher = cbc_module(iv, key)
        ciphertext = cipher.cbc_encrypt(plaintext)
        return ciphertext

    def decrypt(self, iv, key, ciphertext):
        cipher = cbc_module(iv, key)
        plaintext = cipher.cbc_decrypt(ciphertext)
        padding = int.from_bytes(plaintext[-1:], 'big')
        plaintext = plaintext[:-padding]
        return plaintext


def private_protocol():

    print("=== Standard Protocol ===")

    # Step 1
    # A > B - Send p, g, A
    print("[+] Step 1: A > B - Send p, g, A")
    DH_A = DH()
    A = DH_A.generate_public_key(p, g)
    print("> p =", p)
    print("> g =", g)
    print("> A =", A)

    # Step 2
    # B > A - Send B
    print("[+] Step 2: B > A - Send B")
    DH_B = DH()
    B = DH_B.generate_public_key(p, g)
    print("> B =", B)

    # Step 3
    # A > B - Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    #shared_secret_A = DH_A.generate_shared_secret(B, p)
    encryption_key_A = DH_A.generate_encryption_key(B, p)
    iv_A = get_random_bytes(16)

    #cipher_A = cbc_module(iv_A, encryption_key_A)
    ciphertext_A = DH_A.encrypt(iv_A, encryption_key_A, secret_message) + iv_A
    print("[+] Step 3: A > B:", ciphertext_A)

    # Step 4
    # B > A - Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
    encryption_key_B = DH_B.generate_encryption_key(A, p)
    iv_B = ciphertext_A[-16:]
    plaintext_AtoB = DH_B.decrypt(iv_B, encryption_key_B, ciphertext_A[:-16])
    ciphertext_B = DH_B.encrypt(iv_B, encryption_key_B, plaintext_AtoB) + iv_B
    print("[+] Step 4: B > A:", ciphertext_B)
    print("=== END ===")


def MITM():

    print("=== MITM ===")

    # Step 1
    # A > M: Send p, g, A
    print("[+] Step 1: A > B - Send p, g, A")
    DH_A = DH()
    A = DH_A.generate_public_key(p, g)

    # Step 2
    # M > B: Send p, g, p
    print("[*] Step 2 - Intercepted: M > B: Send p, g, p")
    A = p

    # Step 3
    # B > M: Send B
    print("[+] Step 3: B > A - Send B")
    DH_B = DH()
    B = DH_B.generate_public_key(p, g)

    # Step 4
    # M > A: Send p
    print("[*] Step 4 - Intercepted: M > A: Send p")
    B = p

    # Step 5
    # A > M: Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    encryption_key_A = DH_A.generate_encryption_key(B, p)
    iv_A = get_random_bytes(16)
    ciphertext_A = DH_A.encrypt(iv_A, encryption_key_A, secret_message) + iv_A
    print("[+] Step 5: A > B:", ciphertext_A)

    # Step 6
    # M->B: Relay that to B
    print("[-] Step 6: M->B: Relay that to B")

    # Step 7
    # B > M: Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
    encryption_key_B = DH_B.generate_encryption_key(A, p)
    iv_B = ciphertext_A[-16:]
    plaintext_AtoB = DH_B.decrypt(iv_B, encryption_key_B, ciphertext_A[:-16])
    ciphertext_B = DH_B.encrypt(iv_B, encryption_key_B, plaintext_AtoB) + iv_B
    print("[+] Step 4: B > A:", ciphertext_B)

    # Step 8
    # M > A: Relay that to A
    print("[-] Step 8: M > A: Relay that to A")

    # Step 9
    DH_M = DH()
    encryption_key_M = DH_M.generate_encryption_key(p, p)
    iv_M = iv_B
    plaintext_M = DH_M.decrypt(iv_M, encryption_key_M, ciphertext_A[:-16])
    print(plaintext_M)

    if plaintext_M == secret_message:
        print("--- Success ---")

    print("=== END ===")


def main():
    private_protocol()
    MITM()


if __name__ == '__main__':
    main()
