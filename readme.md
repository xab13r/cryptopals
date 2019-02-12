# Matasano Crypto Challenges

A repo for my solutions to the Matasano Crypto Challenges.
All solutions are written for Python 3.x, unless specified.

## Set 01 - Basics
- [x] Challenge 01 - [Convert hex to base64](https://github.com/xab13r/cryptopals/blob/master/set01challenge01.py)
- [x] Challenge 02 - [Fixed XOR](https://github.com/xab13r/cryptopals/blob/master/set01challenge02.py)
- [x] Challenge 03 - [Single-byte XOR cipher](https://github.com/xab13r/cryptopals/blob/master/set01challenge03.py)
- [x] Challenge 04 - [Detect single-character XOR](https://github.com/xab13r/cryptopals/blob/master/set01challenge04.py)
- [x] Challenge 05 - [Implement repeating-key XOR](https://github.com/xab13r/cryptopals/blob/master/set01challenge05.py)
- [x] Challenge 06 - [Break repeating-key XOR](https://github.com/xab13r/cryptopals/blob/master/set01challenge06.py)
- [x] Challenge 07 - [AES in ECB mode](https://github.com/xab13r/cryptopals/blob/master/set01challenge07.py)
- [x] Challenge 08 - [Detect AES in ECB mode](https://github.com/xab13r/cryptopals/blob/master/set01challenge08.py)

## Set 02 - Block crypto
- [x] Challenge 09 - [Implement PKCS#7 padding](https://github.com/xab13r/cryptopals/blob/master/set02challenge09.py)
- [x] Challenge 10 - [Implement CBC mode](https://github.com/xab13r/cryptopals/blob/master/set02challenge10.py)
- [x] Challenge 11 - [An ECB/CBC detection oracle](https://github.com/xab13r/cryptopals/blob/master/set02challenge11.py)
- [x] Challenge 12 - [Byte-at-a-time ECB decryption (Simple)](https://github.com/xab13r/cryptopals/blob/master/set02challenge12.py)
- [x] Challenge 13 - [ECB cut-and-paste](https://github.com/xab13r/cryptopals/blob/master/set02challenge13.py)
- [x] Challenge 14 - [Byte-at-a-time ECB decryption (Harder)](https://github.com/xab13r/cryptopals/blob/master/set02challenge14.py)
- [x] Challenge 15 - [PKCS#7 padding validation](https://github.com/xab13r/cryptopals/blob/master/set02challenge15.py)
- [x] Challenge 16 - [CBC bitflipping attacks](https://github.com/xab13r/cryptopals/blob/master/set02challenge16.py)

## Set 03 - Block & stream crypto
- [x] Challenge 17 - [The CBC padding oracle](https://github.com/xab13r/cryptopals/blob/master/set03challenge17.py)
- [x] Challenge 18 - [Implement CTR, the stream cipher mode](https://github.com/xab13r/cryptopals/blob/master/set03challenge18.py)
- [x] Challenge 19 - [Break fixed-nonce CTR mode using substitutions](https://github.com/xab13r/cryptopals/blob/master/set03challenge19.py)
- [x] Challenge 20 - [Break fixed-nonce CTR statistically](https://github.com/xab13r/cryptopals/blob/master/set03challenge20.py)
- [ ] Challenge 21 - Implement the MT19937 Mersenne Twister RNG
- [ ] Challenge 22 - Crack an MT19937 seed
- [ ] Challenge 23 - Clone an MT19937 RNG from its output
- [ ] Challenge 24 - Create the MT19937 stream cipher and break it

## Set 04 - Stream crypto and randomness
- [ ] Challenge 25 - Break "random access read/write" AES CTR
- [ ] Challenge 26 - CTR bitflipping
- [ ] Challenge 27 - Recover the key from CBC with IV=Key
- [ ] Challenge 28 - Implement a SHA-1 keyed MAC
- [ ] Challenge 29 - Break a SHA-1 keyed MAC using length extension
- [ ] Challenge 30 - Break an MD4 keyed MAC using length extension
- [ ] Challenge 31 - Implement and break HMAC-SHA1 with an artificial timing leak
- [ ] Challenge 32 - Break HMAC-SHA1 with a slightly less artificial timing leak

## Set 05 - Diffie-Hellman and friends
- [ ] Challenge 33 - Implement Diffie-Hellman
- [ ] Challenge 34 - Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
- [ ] Challenge 35 - Implement DH with negotiated groups, and break with malicious "g" parameters
- [ ] Challenge 36 - Implement Secure Remote Password (SRP)
- [ ] Challenge 37 - Break SRP with a zero key
- [ ] Challenge 38 - Offline dictionary attack on simplified SRP
- [ ] Challenge 39 - Implement RSA
- [ ] Challenge 40 - Implement an E=3 RSA Broadcast attack

## Set 06 - RSA and DSA
- [ ] Challenge 41 - Implement unpadded message recovery oracle
- [ ] Challenge 42 - Bleichenbacher's e=3 RSA Attack
- [ ] Challenge 43 - DSA key recovery from nonce
- [ ] Challenge 44 - DSA nonce recovery from repeated nonce
- [ ] Challenge 45 - DSA parameter tampering
- [ ] Challenge 46 - RSA parity oracle
- [ ] Challenge 47 - Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)
- [ ] Challenge 48 - Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)

## Set 07 - Hashes
- [ ] Challenge 49 - CBC-MAC Message Forgery
- [ ] Challenge 50 - Hashing with CBC-MAC
- [ ] Challenge 51 - Compression Ratio Side-Channel Attacks
- [ ] Challenge 52 - Iterated Hash Function Multicollisions
- [ ] Challenge 53 - Kelsey and Schneier's Expandable Messages
- [ ] Challenge 54 - Kelsey and Kohno's Nostradamus Attack
- [ ] Challenge 55 - MD4 Collisions
- [ ] Challenge 56 - RC4 Single-Byte Biases

## Set 08 - Abstract Algebra
- [ ] Challenge 57 - Diffie-Hellman Revisited: Small Subgroup Confinement
- [ ] Challenge 58 - Pollard's Method for Catching Kangaroos
- [ ] Challenge 59 - Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks
- [ ] Challenge 60 - Single-Coordinate Ladders and Insecure Twists
- [ ] Challenge 61 - Duplicate-Signature Key Selection in ECDSA (and RSA)
- [ ] Challenge 62 - Key-Recovery Attacks on ECDSA with Biased Nonces
- [ ] Challenge 63 - Key-Recovery Attacks on GCM with Repeated Nonces
- [ ] Challenge 64 - Key-Recovery Attacks on GCM with a Truncated MAC