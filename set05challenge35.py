'''

Matasano Crypto Challenges
Set 05 - Challenge 35

IMPLEMENT DH WITH NEGOTIATED GROUPS, AND BREAK WITH MALICIOUS "G" PARAMETERS

'''


def main():
    print("[+] Case 1: g = 1")
    print("In this case pow(1, a, p) will always yield A = 1")
    print("B will calculate the shared secret as pow(1, b, p), always equal to 1")

    print("[+] Case 2: g = p")
    print("In this case pow(p, a, p) will always yield A = 0")
    print("B will calculate the shared secret as pow(0, b, p), alwats equal to 0")

    print("[+] Case 3: g = p - 1")
    print("1. If a is even, then pow(p - 1, a, p) will yield A = 1")
    print("B will calculate the shared secret as pow(1, b, p), always equal to 1")
    print("2. If a is odd, then pow(p - 1, a, p) will yield A = p - 1")
    print("B will calculate the shared secret as pow(p, b, p), that based on the value of b, will yield either p - 1 or 1")

if __name__ == '__main__':
    main()
