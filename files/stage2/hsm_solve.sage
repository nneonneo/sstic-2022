import sys
import random

modulus = x^64
n = 0x247f43cb7
for i in range(64):
    if n & (1 << i):
        modulus += x ^ i

K.<a> = GF(2^64, modulus=modulus)

msg1, sig1, msg2, sig2 = [K.fetch_int(int(c)) for c in sys.argv[1:]]
k1_3 = (sig1 - sig2) / (msg1 - msg2)
k1k2 = sig1 - msg1 * k1_3
assert k1k2 == sig2 - msg2 * k1_3

k1s = k1_3.nth_root(3, all=True)
for k1 in k1s:
    k2 = k1k2 / k1
    print(k1.integer_representation(), k2.integer_representation())
