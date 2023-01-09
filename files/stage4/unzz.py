from collections import defaultdict
import sys

class BitReader:
    def __init__(self, data):
        self.pos = 0
        self.data = data

    def __len__(self):
        return len(self.data) * 8

    def read(self, n):
        val = 0
        while n > 0:
            bits = (self.data[self.pos >> 3] << (self.pos % 8)) & 0xff
            take = min(n, 8 - (self.pos % 8))
            val = (val << take) | (bits >> (8 - take))
            n -= take
            self.pos += take
        return val

    def read24(self):
        assert self.pos % 8 == 0
        a, b, c = self.data[self.pos >> 3:(self.pos >> 3) + 3]
        self.pos += 24
        return (a + (b << 8) + (c << 16))

    def pad(self):
        rem = self.pos % 8
        if rem:
            self.pos += 8 - rem


class HuffmanTables:
    def __init__(self, reader, max_bins):
        nbits = max_bins.bit_length() - 1
        nbins = reader.read(nbits) + 1
        bins = [(reader.read(nbits), reader.read(4) + 1) for _ in range(nbins)]
        reader.pad()

        self.bins = bins
        self.codes_by_length = defaultdict(dict)
        self.min_length = 999
        prevdepth = -1
        code = 0
        for val, depth in bins:
            if prevdepth == depth:
                code += 1
            elif prevdepth != -1:
                code = (code + 1) << (depth - prevdepth)
            prevdepth = depth
            self.min_length = min(depth, self.min_length)
            self.codes_by_length[depth][code] = val

    def read(self, reader):
        length = self.min_length
        code = reader.read(self.min_length)
        while code not in self.codes_by_length[length]:
            length += 1
            code = (code << 1) + reader.read(1)
        return self.codes_by_length[length][code]


def read_match_lit(huff, reader):
    n = huff.read(reader)
    if n < 0x10: return n
    nbits = n - 0xc
    return reader.read(nbits) | (1 << nbits)

def read_match_off(huff, reader):
    n = huff.read(reader)
    if n < 2: return n
    nbits = n - 1
    return reader.read(nbits) | (1 << nbits)

def read_match_len(huff, reader):
    n = huff.read(reader)
    if n < 0x10: return n
    nbits = n - 0xc
    return reader.read(nbits) | (1 << nbits)

r = BitReader(open(sys.argv[1], "rb").read())
outf = open(sys.argv[1].replace(".zz", ""), "wb")

while r.pos < len(r):
    outblock = bytearray()

    print("block at %d" % (r.pos // 8))
    blocksize = r.read24()
    blockstart = r.pos

    num_literals = r.read24()
    compressed_literals_len = r.read24()
    startpos = r.pos
    lit_huff = HuffmanTables(r, 0x100)
    lits = bytes([lit_huff.read(r) for _ in range(num_literals)])
    r.pad()
    assert r.pos == startpos + compressed_literals_len * 8

    num_matches = r.read24()

    match_lit_huff = HuffmanTables(r, 0x20)
    match_lits = [read_match_lit(match_lit_huff, r) for _ in range(num_matches)]
    r.pad()

    match_off_huff = HuffmanTables(r, 0x20)
    match_offs = [read_match_off(match_off_huff, r) for _ in range(num_matches)]
    r.pad()

    match_len_huff = HuffmanTables(r, 0x20)
    match_lens = [read_match_len(match_len_huff, r) for _ in range(num_matches)]
    r.pad()

    assert r.pos == blockstart + blocksize * 8
    assert sum(match_lits) == num_literals

    litpos = 0
    for i in range(num_matches):
        match_lit = match_lits[i]
        match_off = match_offs[i]
        match_len = match_lens[i]
        outblock += lits[litpos:litpos+match_lit]
        litpos += match_lit
        if match_len:
            m = outblock[-match_off:]
            m = m * ((match_len + len(m) - 1) // len(m))
            outblock += m[:match_len]
    outf.write(outblock)
