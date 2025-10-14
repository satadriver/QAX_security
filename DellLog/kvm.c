

#include "kvm.h"





int get_proc_by_pid_kvmprocs(pid_t pid, struct proc *proc_out) {
    kvm_t *kd;
    char errbuf[1024];
    struct kinfo_proc2 *procs;
    int nprocs, i;
    
    kd = kvm_openfiles(NULL, NULL, NULL, 0, errbuf);
    if (kd == NULL) {
        fprintf(stderr, "kvm_openfiles failed: %s\n", errbuf);
        return -1;
    }
	
	char readbuf[1024]={0};
	int ret = kvm_read(kd,0x0807880C,readbuf,4);
	if(ret){
		fprintf(stderr, "value: %x\n", *(unsigned int*)readbuf);
	}
    
    // 获取所有进程信息
    procs = kvm_getproc2(kd, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc2), &nprocs);
    if (procs == NULL) {
        fprintf(stderr, "kvm_getproc2 failed: %s\n", kvm_geterr(kd));
        kvm_close(kd);
        return -1;
    }
    
    // 查找目标 PID
    for (i = 0; i < nprocs; i++) {
        if (procs[i].p_pid == pid) {
            // kinfo_proc2 到 proc 的转换需要额外工作
            printf("PID:%d,process:%s\r\n", procs[i].p_pid, procs[i].p_comm);
            break;
        }
    }
	
	/*
	int nvmes;
	struct kinfo_vmentry *vmes;
	vmes = kvm_getvmmap(kd, pid, &nvmes);
    if (vmes == NULL) {
        kvm_close(kd);
        return 0;
    }
	*/
    
    //free(procs);
    kvm_close(kd);
    return (i < nprocs) ? 0 : -1;
}
















/*
struct nlist {
    const char *n_name;  
    uintptr_t   n_value; 
    uint8_t     n_type;  
    int8_t      n_desc;  
    uint8_t     n_other; 
};
*/

struct nlist symbols[] = {
    { "_allproc",0,0,0,0 },      // 所有进程链表
    { "_nprocesses",0,0,0,0 },   // 进程数量
    { NULL }
};



int find_proc_by_pid(pid_t target_pid, struct proc *proc_out) {
	
    u_long allproc_addr;
    struct proc *first_proc;
    int found = 0;
	
	kvm_t *kd=0;
    char errbuf[1024];  
    kd = kvm_openfiles(NULL, NULL, NULL, 0, errbuf);
    if (kvm_nlist(kd, symbols) == -1) {
        fprintf(stderr, "kvm_nlist failed\n");
        return -1;
    }
	
	printf("name:%s,value:%x,type:%d,desc:%d,other:%d\r\n",symbols[0].n_name,symbols[0].n_value,symbols[0].n_type,symbols[0].n_desc,symbols[0].n_other);
    
    if (kvm_read(kd, symbols[0].n_value, &allproc_addr, sizeof(allproc_addr)) == -1) {
        fprintf(stderr, "read allproc err:%s\n",kvm_geterr(kd));
		
        return -1;
    }
    

    if (kvm_read(kd, allproc_addr, &first_proc, sizeof(first_proc)) == -1) {
        fprintf(stderr, "kvm_read failed:%s\n",kvm_geterr(kd));
        return -1;
    }
    
    printf("look forward PID=%d...\n", target_pid);
    
    // 遍历进程链表
    u_long current_addr = (u_long)first_proc;
    int count = 0;
    
    while (current_addr != 0 && current_addr != allproc_addr && count < 1000) {
        struct proc current_proc;
        
        // 读取当前进程结构
        if (kvm_read(kd, current_addr, &current_proc, sizeof(current_proc)) == -1) {
            fprintf(stderr, "read proc struct error at 0x%lx\n", current_addr);
            break;
        }
        
        count++;
        
        // 检查是否为目标进程
        if (current_proc.p_pid == target_pid) {
            *proc_out = current_proc;
            found = 1;
            printf("find target process,count:%d\n", count);
            break;
        }
        
        // 移动到下一个进程 (根据 NetBSD 的链表实现)
        if (current_proc.p_list.le_next == 0) {
            break;
        }
        current_addr = (u_long)current_proc.p_list.le_next;
        
        if (current_addr == allproc_addr) {
            break; // 回到链表头
        }
    }
    
    if (!found) {
        printf("not found PID:%d (get process:%d)\n", target_pid, count);
    }
    
	kvm_close(kd);
    return found ? 0 : -1;
}









typedef uint32_t vm_offset_t;

struct kinfo_vmentry {
    vm_offset_t  vme_start;    /* 虚拟内存区域起始地址 */
    vm_offset_t  vme_end;      /* 虚拟内存区域结束地址（不含） */
    vm_prot_t    vme_prot;     /* 当前保护权限（读/写/执行） */
    vm_prot_t    vme_maxprot;  /* 最大允许的保护权限 */
    int          vme_type;     /* 内存区域类型（匿名/文件等） */
    int          vme_state;    /* 区域状态（活跃/换出等） */
    pid_t        vme_pid;      /* 所属进程ID */
    u_int        vme_npages;   /* 区域包含的页面数量 */
    off_t        vme_offset;   /* 若为文件映射，文件内偏移量 */
    dev_t        vme_dev;      /* 关联文件/设备的设备号 */
    ino_t        vme_ino;      /* 关联文件的inode号 */
    mode_t       vme_mode;     /* 关联文件的权限模式 */
    char         vme_path[32]; /* 若为文件映射，文件路径（短路径） */
};

// 获取目标进程的内存区域信息（kinfo_vmentry）
int get_proc_vm_regions(pid_t pid) {
	
	/* 顶层标识符 */
#define CTL_UNSPEC   0    /* 未指定 */
#define CTL_KERN     1    /* 通用内核信息 */
#define CTL_VM       2    /* 虚拟内存 */
#define CTL_NET      3    /* 网络 */
#define CTL_PROC     4    /* 进程信息 */
#define CTL_FS       5    /* 文件系统 */
#define CTL_DEBUG    6    /* 调试信息 */
#define CTL_DEV      7    /* 设备 */
#define CTL_USER     8    /* 用户级信息 */
#define CTL_DDB      9    /* 内核调试器 */
#define CTL_VFS      10   /* 虚拟文件系统 */
#define CTL_MAXID    11   /* 顶层标识符数量 */

#define KVME_PROT_EXEC    0x04    /* 页面可执行 */

/* KERN_PROC 子类 */
#define KERN_PROC_ALL        0    /* 所有进程 */
#define KERN_PROC_PID        1    /* 按 PID */
#define KERN_PROC_PGRP       2    /* 按进程组 */
#define KERN_PROC_SESSION    3    /* 按会话 */
#define KERN_PROC_TTY        4    /* 按 TTY */
#define KERN_PROC_UID        5    /* 按 UID */
#define KERN_PROC_RUID       6    /* 按真实 UID */
#define KERN_PROC_ARGS       7    /* 进程参数 */
#define KERN_PROC_CWD        8    /* 当前工作目录 */
#define KERN_PROC_NTHREADS   9    /* 线程数 */
//#define KERN_PROC_VMMAP      10   /* 虚拟内存映射 */
#define KERN_PROC_PATH       11   /* 进程路径 */
#define KERN_PROC_ARGLEN     12   /* 参数长度 */
#define KERN_PROC_KSTACK     13   /* 内核栈 */
#define KERN_PROC_SEGS       14   /* 进程段 */
#define KERN_PROC_SV_NAME    15   /* 共享对象名称 */


#define KERN_PROC           35   /* 进程信息 (传统) */
#define KERN_PROC2          36   /* 扩展进程信息 */


#define CTL_KERN          1
#define KERN_PROC2       36
#define KERN_PROC_VMMAP  40
	
    // sysctl参数：查询进程的虚拟内存区域
    // mib[0] = CTL_KERN
    // mib[1] = KERN_PROC_VMMAP （获取虚拟内存映射）
    // mib[2] = pid （目标进程PID）
    int mib[] = { CTL_KERN, KERN_PROC2,KERN_PROC_VMMAP, pid ,sizeof(struct kinfo_vmentry),0};
    size_t mib_len = sizeof(mib) / sizeof(mib[0]);

    // 第一步：获取所需缓冲区大小
    size_t buf_len=0;
    if (sysctl(mib, mib_len, NULL, &buf_len, NULL, 0) == -1) {
		
		int error_code = errno;
        const char *error_str = strerror(error_code);
        
        printf("sysctl failed with error %d: %s\n", error_code, error_str);
		
        return -1;
    }

    // 分配缓冲区存储内存区域信息
    struct kinfo_vmentry *vm_entries = malloc(buf_len);
    if (vm_entries == NULL) {
        perror("内存分配失败");
        return -1;
    }

    // 第二步：获取内存区域数据
    if (sysctl(mib, mib_len, vm_entries, &buf_len, NULL, 0) == -1) {
        perror("sysctl获取内存区域失败");
        free(vm_entries);
        return -1;
    }

    // 遍历内存区域并打印关键信息
    size_t nentries = buf_len / 80;
    printf("进程%d的内存区域（共%d个）：\n", pid, nentries);
	size_t i = 0;
    for ( i = 0; i < nentries; i++) {
        //struct kinfo_vmentry *entry = &vm_entries[i];
		
		unsigned int  *v = (unsigned int  *)&vm_entries[i];
        printf(
            "地址范围: 0x%lx - 0x%lx | 权限: %c%c%c | 类型: %s\n",
			/*
            entry->kve_start,
            entry->kve_end,
            (entry->kve_prot & KVME_PROT_READ) ? 'r' : '-',
            (entry->kve_prot & KVME_PROT_WRITE) ? 'w' : '-',
            (entry->kve_prot & KVME_PROT_EXEC) ? 'x' : '-',
            entry->kve_path  // 映射的文件路径（如无则为NULL）
			*/
			v[0],
            v[1],
            (v[2] & KVME_PROT_READ) ? 'r' : '-',
            (v[2] & KVME_PROT_WRITE) ? 'w' : '-',
            (v[2] & KVME_PROT_EXEC) ? 'x' : '-',
            v[12]  // 映射的文件路径（如无则为NULL）
        );
    }

    free(vm_entries);
    return 0;
}
















// 从内核符号表获取进程链表头地址（需通过nm /netbsd | grep allproc 确认）
#define PROC_LIST_ADDR 0xc0b82bf4  // 示例地址，需替换




// 虚拟地址转物理地址（解析页表）
paddr_t virt_to_phys(kvm_t *kd, struct pmap *pmap, vaddr_t vaddr) {
    unsigned long pdir_pa;       // 页目录物理地址
    unsigned long pdir_entry; // 页目录项
    unsigned long ptab_pa;       // 页表物理地址
    unsigned long ptab_entry; // 页表项
    vaddr_t pdir_idx, ptab_idx;

    // 读取页目录基地址（来自pmap结构体，需根据实际定义调整）
    //if (kvm_read(kd, (vaddr_t)(pmap->pm_pdir), &pdir_pa, sizeof(pdir_pa)) != sizeof(pdir_pa)) 
	{
		fprintf(stderr, "read pm_pdir: %s\n", kvm_geterr(kd));
        return 0;
    }

    // 计算页目录和页表索引（32位系统示例，4KB页）
    pdir_idx = (vaddr >> 22) & 0x3ff;  // 页目录索引（10位）
    ptab_idx = (vaddr >> 12) & 0x3ff;  // 页表索引（10位）

    // 读取页目录项
    if (kvm_read(kd, pdir_pa + pdir_idx * sizeof(pdir_entry), &pdir_entry, sizeof(pdir_entry)) != sizeof(pdir_entry)) {
		fprintf(stderr, "read pdir_pa: %s\n", kvm_geterr(kd));
        return 0;
    }
    if (!(pdir_entry)) {  // 页目录项无效
        return 0;
    }

    // 读取页表项
    ptab_pa = (pdir_entry & 0xfffff000);  // PAGE_SHIFT = 12
    if (kvm_read(kd, ptab_pa + ptab_idx * sizeof(ptab_entry), &ptab_entry, sizeof(ptab_entry)) != sizeof(ptab_entry)) {
		fprintf(stderr, "read ptab_pa: %s\n", kvm_geterr(kd));
        return 0;
    }
    if (!(ptab_entry)) {  // 页表项无效
        return 0;
    }

    // 计算物理地址（页帧号 + 页内偏移）
    return (ptab_entry & 0xfffff000) | (vaddr & PAGE_MASK);
}





int writeProcesData(pid_t target_pid, char *vaddr,char * value) {

    vaddr_t target_vaddr = (vaddr_t)vaddr;
    unsigned long new_value = (unsigned long)value;
    char errbuf[1024];

    // 1. 打开内核内存上下文（需root权限）
    kvm_t *kd = kvm_open(NULL, NULL, NULL, O_RDWR, errbuf);  // 注意：需O_RDWR模式
    if (kd == NULL) {
        fprintf(stderr, "kvm_open failed: %s\n", errbuf);
        return 1;
    }

    // 2. 遍历进程链表，找到目标PID的struct proc
    struct proc *proc_list, *target_proc = NULL;
    if (kvm_read(kd, PROC_LIST_ADDR, &proc_list, sizeof(proc_list)) != sizeof(proc_list)) {
        fprintf(stderr, "read PROC_LIST_ADDR: %s\n", kvm_geterr(kd));
        kvm_close(kd);
        return 1;
    }

    struct proc curr_proc;
	struct proc *p = 0;
    for (p = proc_list; p != NULL; p = (struct proc *)(curr_proc.p_list.le_next)) {
        if (kvm_read(kd, (vaddr_t)p, &curr_proc, sizeof(curr_proc)) != sizeof(curr_proc)) {
            break;
        }
        if (curr_proc.p_pid == target_pid) {
            target_proc = p;
            break;
        }
    }

    if (target_proc == NULL) {
        fprintf(stderr, "PID=%d error\n", target_pid);
        kvm_close(kd);
        return 1;
    }


    struct vmspace vmspace;
    if (kvm_read(kd, (vaddr_t)curr_proc.p_vmspace, &vmspace, sizeof(vmspace)) != sizeof(vmspace)) {
        fprintf(stderr, "kvm_read failed: %s\n", kvm_geterr(kd));
        kvm_close(kd);
        return 1;
    }

    struct vm_map vmap;
    if (kvm_read(kd, (unsigned long)&vmspace.vm_map, (void*)&vmap, sizeof(vmap)) != sizeof(vmap)) {
        fprintf(stderr, "read vm_map error: %s\n", kvm_geterr(kd));
        kvm_close(kd);
        return 1;
    }

/*
    // 4. 验证目标地址所在的内存区域是否可写
    struct vm_map_entry entry;
    struct vm_map_entry *curr_entry = vmap.entries;
    int writable = 0;
    while (curr_entry != NULL) {
        if (kvm_read(kd, (vaddr_t)curr_entry, &entry, sizeof(entry)) != sizeof(entry)) {
            break;
        }
        if (target_vaddr >= entry.start && target_vaddr < entry.end) {
            if (entry.protection & VM_PROT_WRITE) {
                writable = 1;
            }
            break;
        }
        curr_entry = entry.next;
    }

    if (!writable) {
        fprintf(stderr, "目标地址0x%lx不可写（无权限或无效）\n", target_vaddr);
        kvm_close(kd);
        return 1;
    }
	*/

    paddr_t phys_addr = virt_to_phys(kd, vmap.pmap, target_vaddr);
    if (phys_addr == 0) {
        fprintf(stderr, "虚拟地址转物理地址失败\n");
        kvm_close(kd);
        return 1;
    }


    ssize_t nwritten = kvm_read(kd, phys_addr, &new_value, sizeof(new_value));
    if (nwritten != sizeof(new_value)) {
        fprintf(stderr, "kvm_write error: %s\n", kvm_geterr(kd));
        kvm_close(kd);
        return 1;
    }

    printf("kvm_read process:%d address：0x%lx（physical address:0x%lx） value:0x%lx\r\n",
           target_pid, target_vaddr, phys_addr, new_value);

    kvm_close(kd);
    return 0;
}
