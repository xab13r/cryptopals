'''

Matasano Crypto Challenges
Set 02 - Challenge 13

ECB CUT & PASTE

'''

from Crypto.Random import get_random_bytes
from set02challenge11 import ecb_module

kv = 'foo=bar&baz=qux&zap=zazzle'


def kv_decode(input_string):
    parsed_dictionary = {}
    for i in input_string.split('&'):
        parsed_dictionary[i.split('=')[0]] = i.split('=')[1]
    return parsed_dictionary


def kv_encode(input_dictionary):

    kv_list = [item[0] + "=" + item[1] for item in input_dictionary]
    kv_encoded = ''

    for kv in kv_list:
        if kv_encoded != '':
            kv_encoded += '&'
        kv_encoded += kv

    return kv_encoded


def profile_for(input_string):
    if ('&' or '=') in str(input_string):
        raise Exception("Error - Invalid input")

    profile_dictionary = [
        ['email', input_string],
        ['uid', '10'],
        ['role', 'user']
    ]

    return kv_encode(profile_dictionary)


def encrypt_profile(encoded_profile, random_key):
    cipher = ecb_module()
    ciphertext = cipher.ecb_encrypt(
        bytes(encoded_profile, 'utf-8'), random_key)
    return ciphertext


def decrypt_profile(encrypted_profile, random_key):
    cipher = ecb_module()
    plaintext = cipher.ecb_decrypt(encrypted_profile, random_key)
    return plaintext


def main():
    '''
    Because ECB is deterministic, i.e. the same plaintext will always produce the same ciphertexts, we know that the encoded profile for foo@bar.com will produce:

    email=foo@bar.com&uid=10&role=user

    That can be split in 16 bytes blocks with padding before encryption:

    email=foo@bar.co | m&uid=10&role=us | er + padding

    This is a chosen-ciphertext attack, custom email address are allowed. Let's pick:

    '''
    email1 = 'fooo@baar.com'
    email2 = 'foo@bar.coadmin' + '\x0b' * 11

    '''
    Encoding the two email addresses:

    16 bytes blocks for email1:
    email=foo@baar.c | om&uid=10&role= | user + padding

    16 bytes blocks for email2:
    email=foo@bar.co | admin x0b * 11 | user + padding
    '''

    random_key = get_random_bytes(16)
    encrypted_email1 = encrypt_profile(profile_for(email1), random_key)
    encrypted_email2 = encrypt_profile(profile_for(email2), random_key)

    '''
    Swapping blocks
    '''

    target1 = encrypted_email1[0:32]
    target2 = encrypted_email2[16:32]

    print(decrypt_profile(target1 + target2, random_key))


if __name__ == "__main__":
    main()
