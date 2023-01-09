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