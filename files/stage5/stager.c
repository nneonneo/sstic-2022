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
