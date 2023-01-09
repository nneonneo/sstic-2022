# apt install libelf-dev gcc-avr avr-libc libglu1-mesa-dev freeglut3-dev qemu-system-x86

simavr:
	git clone https://github.com/buserror/simavr.git
	cd simavr; git checkout ea4c4504d15117223a23e2dd6edb745fea61ceae
	cd simavr; git apply ../simavr.patch
	cd simavr; make

run: simavr
	GOODFS_PASSWD=goodfspassword K1=123 K2=456 ./simavr/examples/board_simduino/obj-x86_64-linux-gnu/simduino.elf ./chall.hex&
	./start_vm.sh
