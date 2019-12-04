'''

Matasano Crypto Challenges
Set 05 - Challenge 36

IMPLEMENT SECURE REMOTE PASSWORD (SRP)

'''

from random import randint
import hashlib
from os import urandom as get_random_bytes
from set04challenge28 import auth_SHA1

N = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16)

g = 2
k = 3
I = 'test@account.com'
P = b'thisismypassword'


class DH_Server(object):
    
    def __init__(self, N, g, k):
        self.private_key = randint(0, 1024) % 37
        self.N = N
        self.g = g
        self.k = k

    def generate_public_key(self):
        public_key = pow(self.g, self.private_key, self.N)
        return public_key

    def generate_v(self, I, P):
        x = 0
        xH = ''

        salt = get_random_bytes(16)
        xH = hashlib.sha256(salt + P).hexdigest()
        x = int(xH, 16)
        v = pow(self.g, x, self.N)
        return v, salt

    def generate_u(self, A, B):
        A = str(A).encode()
        B = str(B).encode()
        uH = hashlib.sha256(A + B).hexdigest()
        u = int(uH, 16)
        return u

    def generate_B(self, v):
        B = k * v + pow(self.g, self.private_key, self.N)
        return B

    def generate_K(self, A, v, u):
        S = pow(A * pow(v, u, N), self.private_key, N)
        K = hashlib.sha256(str(S).encode()).hexdigest()
        return K


class DH_Client():

    def __init__(self, N, g, k):
        self.private_key = randint(0, 1024) % 37
        self.N = N
        self.g = g
        self.k = k

    def generate_public_key(self):
        public_key = pow(self.g, self.private_key, self.N)
        return public_key

    def generate_u(self, A, B):
        A = str(A).encode()
        B = str(B).encode()
        uH = hashlib.sha256(A + B).hexdigest()
        u = int(uH, 16)
        return u

    def generate_K(self, salt, P, B, u):
        xH = hashlib.sha256(salt + P).hexdigest()
        x = int(xH, 16)
        S = pow(B - self.k * pow(self.g, x, N),
                self.private_key + u * x, self.N)
        K = hashlib.sha256(str(S).encode()).hexdigest()
        return K


def HMAC_SHA256(salt, K):
    K = str(K).encode()
    return hashlib.sha256(salt + K).hexdigest()


def main():
    print("[+] Client & Server agree on N, g, k, email and password")
    client = DH_Client(N, g, k)
    server = DH_Server(N, g, k)

    print("[+] Server generates v and salt")
    v, salt = server.generate_v(I, P)

    print("[+] Client sends I and A")
    A = client.generate_public_key()
    print("I:", I)
    print("A:", A)

    B = server.generate_B(v)
    print("[+] Server sends salt and B")

    print("salt:", salt)
    print("B:", B)

    print("[+] Client and Server generate u")
    client_u = client.generate_u(A, B)
    server_u = server.generate_u(A, B)

    assert client_u == server_u

    print("[+] Server generates K")
    server_K = server.generate_K(A, v, server_u)
    print("[+] Client generates K")
    client_K = client.generate_K(salt, P, B, client_u)

    assert client_K == server_K

    print("Client send M1")
    M1 = HMAC_SHA256(salt, client_K)
    print("Server sends M2")
    M2 = HMAC_SHA256(salt, server_K)

    if M1 == M2:
        print("--- Success ---")

    else:
        raise Exception("*** FAILED ***")


if __name__ == '__main__':
    main()
