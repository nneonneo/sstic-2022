samples = [
    (b"\1\263\200\217\310\241\177\0\0p\24\346\34\377\177\0\0", b"\263\200\217\310\241\177O\f"),
    (b"\1\216&\30?\371U\0\0@\24\346\34\377\177\0\0", b"\216&\30?\371U)\367"),
    (b"\0013'\30?\371U\0\0\20\24\346\34\377\177\0\0", b"3'\30?\371U)\367"),
    (b"\0023'\30?\371U)\367\20\24\346\34\377\177\0\0", b"3'\30?\371U\0\0"),
    (b"\1\220*\30?\371U\0\0\0\0\0\0\0\0\0\0", b"\220*\30?\371UH\361"),
    (b"\1 +\30?\371U\0\0\0\0\0\0\0\0\0\0", b" +\30?\371UH\361"),
    (b"\1\360+\30?\371U\0\0\0\0\0\0\0\0\0\0", b"\360+\30?\371UH\361"),
    (b"\0010-\30?\371U\0\0\0\0\0\0\0\0\0\0", b"0-\30?\371UH\361"),
    (b"\1\2000\30?\371U\0\0\0\0\0\0\0\0\0\0", b"\2000\30?\371UH\361"),
    (b"\1`1\30?\371U\0\0\0\0\0\0\0\0\0\0", b"`1\30?\371UH\361"),
    (b"\1\2002\30?\371U\0\0\0\0\0\0\0\0\0\0", b"\2002\30?\371UH\361"),
    (b"\00103\30?\371U\0\0\0\0\0\0\0\0\0\0", b"03\30?\371UH\361"),
    (b"\1@4\30?\371U\0\0\0\0\0\0\0\0\0\0", b"@4\30?\371UH\361"),
    (b"\1\3005\30?\371U\0\0\0\0\0\0\0\0\0\0", b"\3005\30?\371UH\361"),
    (b"\1\2606\30?\371U\0\0\0\0\0\0\0\0\0\0", b"\2606\30?\371UH\361"),
    (b"\00107\30?\371U\0\0\0\0\0\0\0\0\0\0", b"07\30?\371UH\361"),
    (b"\1\08\30?\371U\0\0\0\0\0\0\0\0\0\0", b"\08\30?\371UH\361"),
    (b"\1P9\30?\371U\0\0\0\0\0\0\0\0\0\0", b"P9\30?\371UH\361"),
    (b"\1\2609\30?\371U\0\0\0\0\0\0\0\0\0\0", b"\2609\30?\371UH\361"),
    (b"\1 <\30?\371U\0\0\0\0\0\0\0\0\0\0", b" <\30?\371UH\361"),
    (b"\1\300>\30?\371U\0\0\0\0\0\0\0\0\0\0", b"\300>\30?\371UH\361"),
    (b"\1 ?\30?\371U\0\0\0\0\0\0\0\0\0\0", b" ?\30?\371UH\361"),
    (b"\1\260?\30?\371U\0\0\0\0\0\0\0\0\0\0", b"\260?\30?\371UH\361"),
    (b"\1\20D\30?\371U\0\0\0\0\0\0\0\0\0\0", b"\20D\30?\371UH\361"),
    (b"\2\216&\30?\371U)\367@\24\346\34\377\177\0\0", b"\216&\30?\371U\0\0"),
    (b"\2\220*\30?\371UH\361\0\0\0\0\0\0\0\0", b"\220*\30?\371U\0\0"),
    (b"\1\255&\30?\371U\0\0P\24\346\34\377\177\0\0", b"\255&\30?\371U)\367"),
    (b"\1\325*\30?\371U\0\0 \24\346\34\377\177\0\0", b"\325*\30?\371U)\367"),
    (b"\1\325*\30?\371U\0\0 \24\346\34\377\177\0\0", b"\325*\30?\371U)\367"),
    (b"\2\325*\30?\371U)\367 \24\346\34\377\177\0\0", b"\325*\30?\371U\0\0"),
    (b"\2 +\30?\371UH\361\0\0\0\0\0\0\0\0", b" +\30?\371U\0\0"),
    (b"\1\367*\30?\371U\0\0\20\24\346\34\377\177\0\0", b"\367*\30?\371U)\367"),
    (b"\2\360+\30?\371UH\361\0\0\0\0\0\0\0\0", b"\360+\30?\371U\0\0"),
    (b"\1\274+\30?\371U\0\0\320\23\346\34\377\177\0\0", b"\274+\30?\371U)\367"),
    (b"\1|,\30?\371U\0\0\260\23\346\34\377\177\0\0", b"|,\30?\371U)\367"),
    (b"\1\232E\30?\371U\0\0\200\23\346\34\377\177\0\0", b"\232E\30?\371U)\367"),
    (b"\2\232E\30?\371U)\367\200\23\346\34\377\177\0\0", b"\232E\30?\371U\0\0"),
    (b"\2|,\30?\371U)\367\260\23\346\34\377\177\0\0", b"|,\30?\371U\0\0"),
    (b"\2\2000\30?\371UH\361\0\0\0\0\0\0\0\0", b"\2000\30?\371U\0\0"),
    (b"\1\235,\30?\371U\0\0\300\23\346\34\377\177\0\0", b"\235,\30?\371U)\367"),
    (b"\2\235,\30?\371U)\367\300\23\346\34\377\177\0\0", b"\235,\30?\371U\0\0"),
    (b"\2\274+\30?\371U)\367\320\23\346\34\377\177\0\0", b"\274+\30?\371U\0\0"),
    (b"\0020-\30?\371UH\361\0\0\0\0\0\0\0\0", b"0-\30?\371U\0\0"),
    (b"\1\342+\30?\371U\0\0\340\23\346\34\377\177\0\0", b"\342+\30?\371U)\367"),
    (b"\2`1\30?\371UH\361\0\0\0\0\0\0\0\0", b"`1\30?\371U\0\0"),
    (b"\1\200-\30?\371U\0\0\240\23\346\34\377\177\0\0", b"\200-\30?\371U)\367"),
    (b"\2\200-\30?\371U)\367\240\23\346\34\377\177\0\0", b"\200-\30?\371U\0\0"),
    (b"\2\260?\30?\371UH\361\0\0\0\0\0\0\0\0", b"\260?\30?\371U\0\0"),
    (b"\1\204/\30?\371U\0\0000\17\346\34\377\177\0\0", b"\204/\30?\371U)\367"),
    (b"\0012@\30?\371U\0\0\340\16\346\34\377\177\0\0", b"2@\30?\371U)\367"),
    (b"\0022@\30?\371U)\367\340\16\346\34\377\177\0\0", b"2@\30?\371U\0\0"),
    (b"\3perms=2&\0\0\0\0\0\0\0\0", b"\201\0332(P\6\212g"),
    (b"\3user=foo\201\0332(P\6\212g", b"4%A\351w|b\r"),
    (b"\2\204/\30?\371U)\3670\17\346\34\377\177\0\0", b"\204/\30?\371U\0\0"),
    (b"\2\342+\30?\371U)\367\340\23\346\34\377\177\0\0", b"\342+\30?\371U\0\0"),
]

import struct

def munge(m, k):
    out = 0
    while m and k:
        if k & 1:
            out ^= m
        if m & 0x8000000000000000:
            m = ((m << 1) ^ 0x247f43cb7) & 0xffffffffffffffff
        else:
            m = (m << 1) & 0xffffffffffffffff
        k >>= 1
    return out

def crypt(m, k, K1, K2):
    m = munge(m, K1)
    m ^= k
    m = munge(m, K1)
    m ^= K2
    m = munge(m, K1)
    return m

if __name__ == "__main__":
    for msg, resp in samples:
        assert len(msg) == 17, "bad len %s" % msg.hex()
        assert len(resp) == 8, "bad len %s" % resp.hex()
        a, b, c = (struct.unpack("<Q", t)[0] for t in (msg[1:9], msg[9:17], resp))
        if msg[0] == 1:
            m, k, c, mask = a, b, c, 0xffff000000000000
        elif msg[0] == 2:
            c, k, m, mask = a, b, c, 0xffff000000000000
        elif msg[0] == 3:
            m, k, c, mask = a, b, c, 0xffffffffffffffff
        else:
            raise Exception("unknown cmd %s" % (msg[:1],))

        outc = crypt(m, k, 123, 456)
        print(f"{m=:016x} {k=:016x} {c=:016x} {mask=:016x} => {outc:016x}")
        assert (c & mask) == (outc & mask)