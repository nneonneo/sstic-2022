# Run a shellcode via sc_runner on qemu.
from pwn import *

s = remote("localhost", 31337)
sc = open("stager", "rb").read()

s.send(sc)
s.recvuntil(b"ready")

sc = open("shellcode", "rb").read()
s.send(p32(len(sc)))
s.send(sc)
s.interactive()
