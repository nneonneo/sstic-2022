all: shellcode

shellcode.i.c: shellcode.c
	cc -E -P $^ > $@

shellcode: shellcode.i.c
	scc -m64 $^ -o $@

stager: stager.c
	scc -m64 $^ -o $@

sc_runner: sc_runner.c
	cc $^ -lseccomp -o $@
