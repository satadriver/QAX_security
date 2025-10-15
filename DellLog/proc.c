#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdint.h>


ssize_t read_process_mem(pid_t pid, uintptr_t addr, void *buf, size_t size) {
    if (buf == NULL || size == 0) {
        fprintf(stderr, "invalid params\n");
        return -1;
    }


    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);


    int fd = open(mem_path, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "open %s failed: %s\n", mem_path, strerror(errno));
        return -1;
    }


    off_t off = lseek(fd, addr, SEEK_SET);
    if (off == -1) {
        fprintf(stderr, "lseek 0x%lx failed: %s\n", addr, strerror(errno));
        close(fd);
        return -1;
    }


    ssize_t bytes_read = read(fd, buf, size);
    if (bytes_read == -1) {
        fprintf(stderr, "read error: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    return bytes_read;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <PID> <address(hex)> <bytes>\n", argv[0]);
        fprintf(stderr, "example: %s 1234 0x7f000000 16\n", argv[0]);
        return 1;
    }


    pid_t pid = atoi(argv[1]);
    uintptr_t addr = strtoull(argv[2], NULL, 16);
    size_t size = atoi(argv[3]);


    uint8_t *buf = malloc(size);
    if (buf == NULL) {
        perror("malloc failed");
        return 1;
    }

	size_t i = 0;

    printf("read pid %d address 0x%lx %zu bytes...\n", pid, addr, size);
    ssize_t ret = read_process_mem(pid, addr, buf, size);
    if (ret > 0) {

        printf("hex data:\n");
        for ( i = 0; i < ret; i++) {
            printf("%02x ", buf[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        if (ret % 16 != 0) printf("\n");


        printf("ASCII data:\n");
        for ( i = 0; i < ret; i++) {
            if (buf[i] >= 32 && buf[i] <= 126) {
                printf("%c", buf[i]);
            } else {
                printf(".");
            }
            if ((i + 1) % 16 == 0) printf("\n");
        }
        if (ret % 16 != 0) printf("\n");
    } else if (ret == 0) {
        printf("read error \n");
    }

    free(buf);
    return 0;
}


