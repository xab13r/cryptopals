'''

Matasano Crypto Challenges
Set 03 - Challenge 23

CLONE AN MT19937 RNG FROM ITS OUTPUT

'''

from set03challenge21 import MT19937
from Crypto.Random.random import randint


def get_bit(number, position):
    # Return the bit at the given position
    if position < 0 or position > 31:
        return 0
    return (number >> (31 - position) & 1)


def set_bit_to_one(number, position):
    # Set bit at position to 1
    return (number | (1 << (31-position)))


def undo_right_shift_xor(output, shift_length):
    # Result of this function is easier if visualized on paper
    original = 0  # Initialize variable for original value
    for i in range(32):
        next_bit = get_bit(output, i) ^ get_bit(original, i - shift_length)
        if next_bit == 1:
            original = set_bit_to_one(original, i)
    return original


def undo_left_shift_xor_and(output, shift_length, and_value):
    # Result of this function is easier if visualized on paper
    original = 0  # Initialize variable for original value
    for i in range(32):
        next_bit = get_bit(output, 31 - i) ^ (get_bit(original,
                                                      31 - (i-shift_length)) & get_bit(and_value, 31-i))
        if next_bit == 1:
            original = set_bit_to_one(original, 31 - i)
    return original


def untemper(y):
    # Reverse all the tempering steps in the RNG
    y = undo_right_shift_xor(y, MT19937.l)
    y = undo_left_shift_xor_and(y, MT19937.t, MT19937.c)
    y = undo_left_shift_xor_and(y, MT19937.s, MT19937.b)
    y = undo_right_shift_xor(y, MT19937.u)
    return y


def get_cloned_MT19937(original_MT19937):
    # Iteration through 624 outputs to recreate the state of the RNG
    state = []
    for i in range(MT19937.n):
        state.append(untemper(original_MT19937.extract_number()))

    cloned_MT19937 = MT19937(0)
    # Splice the state into a cloned instance of the RNG
    cloned_MT19937.state = state

    return cloned_MT19937


def main():
    seed = randint(0, 2**32 - 1)
    # Create a RNG instance
    original_MT19937 = MT19937(seed)
    # Create a clone of the RNG
    cloned_MT19937 = get_cloned_MT19937(original_MT19937)

    # Check that original and cloned RNGs are returning the same 'random' number
    for i in range(1000):
        if original_MT19937.extract_number() != cloned_MT19937.extract_number():
            print("*** FAILED ***")
    print("--- Success ---")


if __name__ == "__main__":
    main()
