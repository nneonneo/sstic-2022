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
