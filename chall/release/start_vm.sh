#!/bin/bash

qemu-system-x86_64 \
    -m 128M \
    -cpu qemu64,+smep,+smap \
    -nographic \
    -no-reboot \
    -serial stdio \
    -kernel ./bzImage \
    -append 'console=ttyS0 loglevel=10 oops=panic panic=10 ip=10.10.10.10:::::eth0:none' \
    -monitor /dev/null \
    -initrd initramfs.img \
    -chardev tty,path=/tmp/simavr-uart0,id=hsm \
    -device pci-serial,chardev=hsm \
    -net user,hostfwd=tcp::31337-10.10.10.10:31500,hostfwd=tcp::33344-10.10.10.10:33344 \
    -net nic
