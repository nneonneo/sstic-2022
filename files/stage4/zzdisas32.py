# Automatically extract instructions from the weird machine

from capstone import *
from struct import unpack_from, calcsize

md = Cs(CS_ARCH_X86, CS_MODE_32)

f = open("zz", "rb")
prog = f.read()

def disas_op_impl(opaddr):
    rip = opaddr + 0x9250 + 0x187
    seen = set()
    while 1:
        if rip in seen: break
        seen.add(rip)
        for i in md.disasm(prog[rip:], rip):
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            if i.mnemonic == "jmp":
                if i.op_str == "esi":
                    return
                rip = int(i.op_str, 0)
                break

pc = 0x10697 + 0x12a

def rd(fmt):
    global pc
    res = unpack_from("<" + fmt, prog, pc)
    pc += calcsize("<" + fmt)
    return res

"""

8fee:   push 0x2b
        pop ds
        push 0x2b
        pop es
        call edi        # esp + 0x4c
247b:   lea eax, [a12a]
        push eax        # esp + 0x48
        call runvm      # esp + 0x44
7d66:   push ebp        # esp + 0x40
        sub esp, 0x40
        mov ebp, esp
        mov eax, [esp+0x50]
        mov [ebp], eax
        mov eax, [esp+0x54]
51cf:   mov [ebp+4], eax
        mov eax, [esp+0x58]
        mov [ebp+8], eax
        mov eax, [esp+0x5c]
        mov [ebp+12], eax
        mov eax, [esp+0x60]
        mov [ebp+16], eax
4b26:   mov edi, [esp+0x48]
        mov edx, esp
        mov [ebp+0x38], edx
        sub esp, 0x100
        mov [ebp+0x28], esp
        mov edx, [edi]
        lea esi, [entry]
        add esi, edx
        jmp esi
"""

# rN = dword [ebp+N*4]
# r0..r4 = function arguments
# r10 = esp (0x100 space)

while 1:
    print(f"{pc:05x}:", end=" ")
    opcode, = rd("I")

    if opcode == 0x2ccd:
        d, a, b = rd("BBB")
        print(f"[r{a}+{b*4}] = r{d}")
    elif opcode == 0x15cb:
        d, imm = rd("BI")
        print(f"r{d} = {imm:#x}")
    elif opcode == 0x1c5e:
        d, a, b = rd("BBB")
        print(f"r{d} = [r{a}+{b*4}]")
    elif opcode == 0x5c34:
        d, = rd("B")
        print(f"r14 -= {d*4}")
    elif opcode == 0x5547:
        d, a, b = rd("BBB")
        if b == 255:
            print(f"r{d} = r{a}")
        else:
            print(f"r{d} = r{a} + r{b}")
    elif opcode == 0x52ac:
        imm, = rd("i")
        print(f"r0 = sub_{imm+0x11111187:#x}(r0, r1, r2, r3, r4)")
    else:
        print(f"UNK_{opcode:04x}")
        disas_op_impl(opcode)
        break

