#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <kvm.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

unsigned long get_base_address_kvm(pid_t pid) {
    kvm_t *kd;
    char errbuf[_POSIX2_LINE_MAX];
    struct kinfo_proc *kp;
    struct kinfo_vmentry *vent;
    int count, vcount;
    unsigned long base_addr = 0;
    
    kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, errbuf);
    if (!kd) {
        fprintf(stderr, "kvm_openfiles failed: %s\n", errbuf);
        return 0;
    }
    
    // 获取进程信息
    kp = kvm_getprocs(kd, KERN_PROC_PID, pid, sizeof(struct kinfo_proc), &count);
    if (!kp || count == 0) {
        fprintf(stderr, "Process %d not found\n", pid);
        kvm_close(kd);
        return 0;
    }
    
    printf("Process: %s (PID: %d)\n", kp->p_comm, pid);
    
    // 获取进程内存映射
    vent = kvm_getvmmap(kd, pid, &vcount);
    if (!vent) {
        fprintf(stderr, "kvm_getvmmap failed: %s\n", kvm_geterr(kd));
        kvm_close(kd);
        return 0;
    }
    
    // 查找可执行文件基地址
    for (int i = 0; i < vcount; i++) {
        printf("Map %d: 0x%lx-0x%lx prot=0x%x %s\n",
               i, vent[i].kve_start, vent[i].kve_end,
               vent[i].kve_protection, vent[i].kve_path);
        
        // 主可执行文件通常是最早加载的具有执行权限的映射
        if ((vent[i].kve_protection & KVME_PROT_EXEC) &&
            vent[i].kve_path[0] != '\0' &&
            strstr(vent[i].kve_path, ".elf") == NULL) { // 排除 .elf 描述文件
            
            if (base_addr == 0 || vent[i].kve_start < base_addr) {
                base_addr = vent[i].kve_start;
            }
        }
    }
    
    if (base_addr != 0) {
        printf("Detected base address: 0x%lx\n", base_addr);
    }
    
    kvm_close(kd);
    return base_addr;
}
