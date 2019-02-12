'''

Matasano Crypto Challenges
Set 03 - Challenge 21

IMPLEMENT THE MT19937 MERSENNE TWISTER RNG

'''


def get_lowest_bits(n, number_of_bits):
    mask = (1 << number_of_bits) - 1
    return n & mask


class MT19937():
    # Implemntation based on Wikipedia pseudo-code
    w, n, m, r = 32, 624, 397, 31  # Word size
    a = 0x9908b0df
    u, d = 11, 0xffffffff
    s, b = 7, 0x9d2c5680
    t, c = 15, 0xefc60000
    l = 18
    f = 1812433253
    lower_mask = (1 << r) - 1
    upper_mask = get_lowest_bits(not lower_mask, w)

    def __init__(self, seed):
        self.state = [0] * self.n  # Initialize state
        self.index = self.n
        self.state[0] = seed

        for i in range(1, self.index):
            self.state[i] = get_lowest_bits(
                self.f * (self.state[i-1] ^ (self.state[i-1] >> (self.w-2))) + i, self.w)

    def extract_number(self):
        if self.index >= self.n:
            if self.index > self.n:
                raise Exception("Generator was never seeded")
            else:
                self.twist()

        y = self.state[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)

        self.index += self.index + 1
        return get_lowest_bits(y, 32)

    def twist(self):
        x = 0
        xA = 0
        for i in range(self.n):
            x = (self.state[i] & self.upper_mask) + \
                (self.state[(i+1) % self.n] & self.lower_mask)
            xA = x >> 1
            if (x % 2) != 0:
                xA = xA ^ self.a
            self.state[i] = self.state[(i + self.m) % self.n] ^ xA

        self.index = 0


def main():
    # Print a bunch of numbers
    for i in range(25):
        print(MT19937(i).extract_number())


if __name__ == "__main__":
    main()
