#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>      // O_RDONLY, O_WRONLY, O_CREAT
#include <unistd.h>     // read, write, close
#include <errno.h>      // errno, perror

#define OUTPUT_FILE "fgtlog.dat"

int main() {
    int fd_in, fd_out;
    char buffer[4096];
    ssize_t bytes_read;

    fd_in = open("/dev/fgtlog", O_RDONLY);
    if (fd_in == -1) {
        perror("open /dev/fgtlog failed");
        return EXIT_FAILURE;
    }

    fd_out = open(OUTPUT_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_out == -1) {
        perror("open out file error");
        close(fd_in);
        return EXIT_FAILURE;
    }

    printf("open /dev/fgtlog ok,write file: %s\n", OUTPUT_FILE);

    while (1) {
        bytes_read = read(fd_in, buffer, sizeof(buffer));
        if (bytes_read == -1) {
			printf("read data error:%d,string:%s\r\n",errno,strerror(errno));
            if (errno != EINTR) {
                
                break;
            }
			break;
            continue;
        } else if (bytes_read == 0) {
            printf("read complete (EOF)\n");
            break;
        } else {
            ssize_t bytes_written = write(fd_out, buffer, bytes_read);
            if (bytes_written != bytes_read) {
                perror("write file error");
                break;
            }
        }
    }

    close(fd_in);
    close(fd_out);
    return EXIT_SUCCESS;
}