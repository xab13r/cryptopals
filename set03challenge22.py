'''

Matasano Crypto Challenges
Set 03 - Challenge 22

CRACK AN MT19937 SEED

'''

from set03challenge21 import MT19937
from Crypto.Random.random import randint
from time import time

# Save current timestamp
timestamp = int(time())


def routine():
    global timestamp
    # Wait 40-1000 seconds
    timestamp += randint(40, 1000)
    # Grab timestamp as a seed
    seed = timestamp
    # Seed the RNG
    MT19937_RNG = MT19937(seed)
    # Wait 40-1000 seconds
    timestamp += randint(40, 1000)
    return seed, MT19937_RNG.extract_number()


def crack_MT19937_seed(rng_output):

    global timestamp
    # Machine may be faster in computing, delay current time by 10 seconds
    guessed_seed = timestamp + 10
    # Seed the RNG
    MT19937_RNG = MT19937(guessed_seed)

    # Decrease timestamp until the RNG returns the same value as the initial one
    print("Cracking seed...")
    while MT19937_RNG.extract_number() != rng_output:
        guessed_seed -= 1
        MT19937_RNG = MT19937(guessed_seed)

    print("--- Cracked ---")
    print("Seed:", guessed_seed)
    # Return cracked seed
    return guessed_seed


def main():

    real_seed, rng_output = routine()
    print("MT19937 Output:", rng_output)
    guessed_seed = crack_MT19937_seed(rng_output)
    if real_seed == guessed_seed:
        print("--- Success ---")


if __name__ == "__main__":
    main()
