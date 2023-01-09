# Automatically extract instructions from the weird machine

from capstone import *
from struct import unpack_from, calcsize

md = Cs(CS_ARCH_X86, CS_MODE_64)

f = open("zz", "rb")
prog = f.read()

def disas_op_impl(opaddr):
    rip = opaddr + 0x1140
    seen = set()
    while 1:
        if rip in seen: break
        seen.add(rip)
        for i in md.disasm(prog[rip:], rip):
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            if i.mnemonic == "jmp":
                if i.op_str == "rdx":
                    return
                rip = int(i.op_str, 0)
                break

# - 0x1000 for file offset
#pc = 0x1338c
#pc = 0x13527 # from sub_0x2e9c
pc = 0x130c0 # from sub_0x2ccc

def rd(fmt):
    global pc
    res = unpack_from("<" + fmt, prog, pc - 0x1000)
    pc += calcsize("<" + fmt)
    return res

# rN = dword [ebp+N*4]
# r0..r4 = function arguments
# r10 = esp (0x100 space)

while 1:
    print(f"{pc:05x}:", end=" ")
    opcode, = rd("I")

    if opcode == 0x4c29:
        c, b, d = rd("BBB")
        print(f"[r{b}+{4*d}] = r{c}")
    elif opcode == 0x4ee7:
        c, b, d = rd("BBB")
        print(f"r{c} = [r{b}+{4*d}]")
    elif opcode == 0x6718:
        c, x = rd("BI")
        print(f"r{c} = {x:#x}")
    elif opcode == 0x634f:
        off, = rd("h")
        print(f"goto {pc+off:05x}")
    elif opcode == 0x4f23:
        c, b, d = rd("BBB")
        print(f"r{c} = r{b} < r{d}")
    elif opcode == 0x2e59:
        d, off = rd("BH")
        print(f"if r{d} == 0: goto {pc+off:05x}")
    elif opcode == 0x7153:
        c, b, d = rd("BBB")
        print(f"r{c} = r{b} - r{d}")
    elif opcode == 0x67b8:
        c, = rd("B")
        print(f"r14 = r14 - {4*c}")
    elif opcode == 0x68c5:
        imm, = rd("i")
        print(f"r0 = sub_{imm+0x1140:#x}(r0, r1, r2, r3, r4)")
    elif opcode == 0x4327:
        c, b, d = rd("BBB")
        print(f"r{c} = r{b} + {4*d}")
    elif opcode == 0x5299:
        c, b, d = rd("BBB")
        if d == 255:
            print(f"r{c} = r{b}")
        else:
            print(f"r{c} = r{b} + r{d}")
    elif opcode == 0x4cf5:
        print("return r0")
        break
    elif opcode == 0x5444:
        c, b, d = rd("BBB")
        print(f"r{c} = [r{b}+r{d}]")
    elif opcode == 0x769b:
        c, b, d = rd("BBB")
        print(f"r{c} = [r{b}+r{d}*4]")
    elif opcode == 0x5727:
        d, off = rd("BH")
        print(f"if r{d} != 0: goto {pc+off:05x}")
    else:
        print(f"UNK_{opcode:04x}")
        disas_op_impl(opcode)
        break

