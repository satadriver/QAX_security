#define _NETBSD_SOURCE  


#include <sys/param.h>
#include <kvm.h>
#include <fcntl.h>      

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <kvm.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <errno.h>


#define ERR_BUF_SIZE 1024


kvm_t* kvm_init(char* errbuf) {
    kvm_t* kd = kvm_openfiles(
        NULL,  
        NULL,   
        NULL,   
        O_RDWR, 
        errbuf  
    );
    if (kd == NULL) {
        snprintf(errbuf, ERR_BUF_SIZE, "kvm_openfiles failed: %s", errbuf);
    }
    return kd;
}


int check_process(kvm_t* kd, pid_t pid, char* errbuf) {
	int cnt = 0;
    struct kinfo_proc* proc = kvm_getprocs(kd, KERN_PROC_PID, pid, &cnt);
    if (proc == NULL) {
        snprintf(errbuf, ERR_BUF_SIZE, "kvm_getprocs failed: %s", kvm_geterr(kd));
        return 0;
    }

    return 1;
}


ssize_t read_process_mem(kvm_t* kd, pid_t pid, unsigned long addr, void* buf, size_t len, char* errbuf) {

    if (!check_process(kd, pid, errbuf)) {
        return -1;
    }

    ssize_t bytes_read = kvm_read(kd, addr, buf, len);
	
    if (bytes_read < 0) {
        snprintf(errbuf, ERR_BUF_SIZE, "kvm_read failed (addr=0x%x): %s", addr, kvm_geterr(kd));
        return -1;
    }
    if ((size_t)bytes_read != len) {
        snprintf(errbuf, ERR_BUF_SIZE, "partial read: expected %u bytes, got %d", len, bytes_read);
    }
    return bytes_read;
}


ssize_t write_process_mem(kvm_t* kd, pid_t pid, unsigned long addr, const void* buf, size_t len, char* errbuf) {

    if (!check_process(kd, pid, errbuf)) {
        return -1;
    }

    ssize_t bytes_written = kvm_write(kd, addr, buf, len);
    if (bytes_written < 0) {
        snprintf(errbuf, ERR_BUF_SIZE, "kvm_write failed (addr=0x%lx): %s", addr, kvm_geterr(kd));
        return -1;
    }
    if ((size_t)bytes_written != len) {
        snprintf(errbuf, ERR_BUF_SIZE, "partial write: expected %zu bytes, got %zd", len, bytes_written);
    }
    return bytes_written;
}


void print_hex_ascii(const void* buf, size_t len) {
    const unsigned char* p = (const unsigned char*)buf;
	size_t i = 0;
    for ( i = 0; i < len; i++) {
        printf("%02x ", p[i]);
        if ((i + 1) % 16 == 0 || i == len - 1) {

            size_t spaces = (16 - (i % 16 + 1)) * 3;
			size_t j = 0;
            for ( j = 0; j < spaces; j++) printf(" ");

            for ( j = i - (i % 16); j <= i; j++) {
                char c = p[j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
            printf("\n");
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <read|write> <pid> <addr(hex)> <len|val>\n", argv[0]);
        fprintf(stderr, "Example:\n");
        fprintf(stderr, "  Read 4 bytes: %s read 1234 0x7f000000 4\n", argv[0]);
        fprintf(stderr, "  Write int 100: %s write 1234 0x7f000000 100\n", argv[0]);
        return 1;
    }


    const char* op = argv[1];
    pid_t pid = atoi(argv[2]);
    unsigned long addr = strtoul(argv[3], NULL, 16); 
    int len_or_val = atoi(argv[4]);

    if (pid <= 0 || addr == 0) {
        fprintf(stderr, "Invalid PID or address\n");
        return 1;
    }

    char errbuf[ERR_BUF_SIZE];
    kvm_t* kd = kvm_init(errbuf);
    if (kd == NULL) {
        fprintf(stderr, "kvm init failed: %s\n", errbuf);
        return 1;
    }
	
    if (strcmp(op, "read") == 0) {
        size_t read_len = (size_t)len_or_val;
        if (read_len <= 0 || read_len > 4096) { 
            fprintf(stderr, "Read length must be 1-4096\n");
            kvm_close(kd);
            return 1;
        }

        void* buf = malloc(read_len+16);
        if (buf == NULL) {
            perror("malloc failed");
            kvm_close(kd);
            return 1;
        }

        ssize_t result = read_process_mem(kd, pid, addr, buf, read_len, errbuf);
        if (result > 0) {
            printf("Successfully read %zd bytes from pid %d, addr 0x%lx:\n", result, pid, addr);
            print_hex_ascii(buf, result);

            if (result == sizeof(int)) {
                printf("As integer: %d\n", *(int*)buf);
            }
        } else {
            fprintf(stderr, "Read failed: %s\n", errbuf);
        }
        free(buf);

    } else if (strcmp(op, "write") == 0) {
        int write_val = len_or_val;
        ssize_t result = write_process_mem(kd, pid, addr, &write_val, sizeof(write_val), errbuf);
        if (result > 0) {
            printf("Successfully wrote %zd bytes to pid %d, addr 0x%lx (value: %d)\n", 
                   result, pid, addr, write_val);

            int verify_val;
            if (read_process_mem(kd, pid, addr, &verify_val, sizeof(verify_val), errbuf) == sizeof(verify_val)) {
                if (verify_val == write_val) {
                    printf("Verification passed: addr 0x%lx = %d\n", addr, verify_val);
                } else {
                    printf("Verification failed: expected %d, got %d\n", write_val, verify_val);
                }
            }

        } else {
            fprintf(stderr, "Write failed: %s\n", errbuf);
        }

    } else {
        fprintf(stderr, "Invalid operation: use 'read' or 'write'\n");
        kvm_close(kd);
        return 1;
    }

    kvm_close(kd);
    return 0;
}
