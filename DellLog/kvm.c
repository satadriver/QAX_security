

#include "kvm.h"

//

//#include <x86/pmap.h>

//#include <uvm/uvm_object.h>


struct uvm_object {
	kmutex_t		vmobjlock;	/* lock on memq */
	const struct uvm_pagerops *pgops;	/* pager ops */
	struct pglist		memq;		/* pages in this object */
	int			uo_npages;	/* # of pages in memq */
	unsigned		uo_refs;	/* reference count */
	struct rb_tree		rb_tree;	/* tree of pages */
};

struct pmap {
	struct uvm_object pm_obj[PTP_LEVELS-1]; /* objects for lvl >= 1) */
#define	pm_lock	pm_obj[0].vmobjlock
	LIST_ENTRY(pmap) pm_list;	/* list (lck by pm_list lock) */
	pd_entry_t *pm_pdir;		/* VA of PD (lck by object lock) */
#ifdef PAE
	paddr_t pm_pdirpa[PDP_SIZE];
#else
	paddr_t pm_pdirpa;		/* PA of PD (read-only after create) */
#endif
	struct vm_page *pm_ptphint[PTP_LEVELS-1];
					/* pointer to a PTP in our pmap */
	struct pmap_statistics pm_stats;  /* pmap stats (lck by object lock) */

#if !defined(__x86_64__)
	vaddr_t pm_hiexec;		/* highest executable mapping */
#endif /* !defined(__x86_64__) */
	int pm_flags;			/* see below */

	union descriptor *pm_ldt;	/* user-set LDT */
	size_t pm_ldt_len;		/* size of LDT in bytes */
	int pm_ldt_sel;			/* LDT selector */
	uint32_t pm_cpus;		/* mask of CPUs using pmap */
	uint32_t pm_kernel_cpus;	/* mask of CPUs using kernel part
					 of pmap */
};

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
    
    procs = kvm_getproc2(kd, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc2), &nprocs);
    if (procs == NULL) {
        fprintf(stderr, "kvm_getproc2 failed: %s\n", kvm_geterr(kd));
        kvm_close(kd);
        return -1;
    }
    

    for (i = 0; i < nprocs; i++) {
        if (procs[i].p_pid == pid) {

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
    { "_allproc",0,0,0,0 },      
    { "_nprocesses",0,0,0,0 },   
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
    

    u_long current_addr = (u_long)first_proc;
    int count = 0;
    
    while (current_addr != 0 && current_addr != allproc_addr && count < 1000) {
        struct proc current_proc;
        

        if (kvm_read(kd, current_addr, &current_proc, sizeof(current_proc)) == -1) {
            fprintf(stderr, "read proc struct error at 0x%lx\n", current_addr);
            break;
        }
        
        count++;
        

        if (current_proc.p_pid == target_pid) {
            *proc_out = current_proc;
            found = 1;
            printf("find target process,count:%d\n", count);
            break;
        }
        

        if (current_proc.p_list.le_next == 0) {
            break;
        }
        current_addr = (u_long)current_proc.p_list.le_next;
        
        if (current_addr == allproc_addr) {
            break; 
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
    vm_offset_t  vme_start;    
    vm_offset_t  vme_end;      
    vm_prot_t    vme_prot;     
    vm_prot_t    vme_maxprot; 
    int          vme_type;    
    int          vme_state;   
    pid_t        vme_pid;      
    u_int        vme_npages;   
    off_t        vme_offset;  
    dev_t        vme_dev;    
    ino_t        vme_ino;    
    mode_t       vme_mode;     
    char         vme_path[32]; 
};


int get_proc_vm_regions(pid_t pid) {

#define CTL_UNSPEC   0    
#define CTL_KERN     1    
#define CTL_VM       2    
#define CTL_NET      3    
#define CTL_PROC     4   
#define CTL_FS       5   
#define CTL_DEBUG    6   
#define CTL_DEV      7    
#define CTL_USER     8    
#define CTL_DDB      9    
#define CTL_VFS      10  
#define CTL_MAXID    11   

#define KVME_PROT_EXEC    0x04    


#define KERN_PROC_ALL        0   
#define KERN_PROC_PID        1   
#define KERN_PROC_PGRP       2   
#define KERN_PROC_SESSION    3    
#define KERN_PROC_TTY        4    
#define KERN_PROC_UID        5    
#define KERN_PROC_RUID       6    
#define KERN_PROC_ARGS       7    
#define KERN_PROC_CWD        8    
#define KERN_PROC_NTHREADS   9    

#define KERN_PROC_PATH       11  
#define KERN_PROC_ARGLEN     12   
#define KERN_PROC_KSTACK     13   
#define KERN_PROC_SEGS       14   
#define KERN_PROC_SV_NAME    15   


#define KERN_PROC           35  
#define KERN_PROC2          36  


#define CTL_KERN          1
#define KERN_PROC2       36
#define KERN_PROC_VMMAP  40
	
    int mib[] = { CTL_KERN, KERN_PROC2,KERN_PROC_VMMAP, pid ,sizeof(struct kinfo_vmentry),0};
    size_t mib_len = sizeof(mib) / sizeof(mib[0]);

    size_t buf_len=0;
    if (sysctl(mib, mib_len, NULL, &buf_len, NULL, 0) == -1) {
		
		int error_code = errno;
        const char *error_str = strerror(error_code);
        
        printf("sysctl failed with error %d: %s\n", error_code, error_str);
		
        return -1;
    }

    struct kinfo_vmentry *vm_entries = malloc(buf_len);
    if (vm_entries == NULL) {
        perror("malloc");
        return -1;
    }

    if (sysctl(mib, mib_len, vm_entries, &buf_len, NULL, 0) == -1) {
        perror("sysctl");
        free(vm_entries);
        return -1;
    }


    size_t nentries = buf_len / 80;
    printf("process:%d memory(total:%d)\n", pid, nentries);
	size_t i = 0;
    for ( i = 0; i < nentries; i++) {
        //struct kinfo_vmentry *entry = &vm_entries[i];
		
		unsigned int  *v = (unsigned int  *)&vm_entries[i];
        printf(
            "range: 0x%lx - 0x%lx | privilige: %c%c%c | type: %s\n",
			v[0],
            v[1],
            (v[2] & KVME_PROT_READ) ? 'r' : '-',
            (v[2] & KVME_PROT_WRITE) ? 'w' : '-',
            (v[2] & KVME_PROT_EXEC) ? 'x' : '-',
            v[12] 
        );
    }

    free(vm_entries);
    return 0;
}

















#define PROC_LIST_ADDR 0xc0b82bf4

#define vaddr_t unsigned long



paddr_t virt_to_phys(kvm_t *kd, struct pmap *pmap, unsigned long vaddr) {
    unsigned long pdir_pa;    
    unsigned long pdir_entry; 
    unsigned long ptab_pa;       
    unsigned long ptab_entry;
    vaddr_t pdir_idx, ptab_idx;
	
	struct pmap mypmap;
	if (kvm_read(kd, (vaddr_t)pmap, &mypmap, sizeof(mypmap)) != sizeof(mypmap)) {
        fprintf(stderr, "kvm_read mypmap failed: %s\n", kvm_geterr(kd));
        kvm_close(kd);
        return 1;
    }
	fprintf(stderr, "read pm_pdirpa: %x\n", mypmap.pm_pdir);
	
    if (kvm_read(kd, mypmap.pm_pdir, &pdir_pa, sizeof(pdir_pa)) != sizeof(pdir_pa)) 
	{
		fprintf(stderr, "read pm_pdir: %s\n", kvm_geterr(kd));
        return 0;
    }
	fprintf(stderr, "read pm_pdir: %x\n", pdir_pa);
	
	int cr3[1024];
	if(kvm_read(kd, pdir_pa, cr3, sizeof(cr3)) != sizeof(cr3)){
		fprintf(stderr, "read cr3: %s\n", kvm_geterr(kd));
		return -1;
	}
	int k = 0;
	for( k = 0;k < 1024;k ++){
		if(k % 0x100 == 0){
			printf("address:%x,value:%x\r\n",cr3+k,cr3[k]);
		}
	}
	
	printf("%s ok\r\n",__FUNCTION__);

    pdir_idx = (vaddr >> 22) & 0x3ff;  
    ptab_idx = (vaddr >> 12) & 0x3ff; 


    if (kvm_read(kd, pdir_pa + pdir_idx * sizeof(pdir_entry), &pdir_entry, sizeof(pdir_entry)) != sizeof(pdir_entry)) {
		fprintf(stderr, "read pdir_pa: %s\n", kvm_geterr(kd));
        return 0;
    }
    if (!(pdir_entry)) { 
		fprintf(stderr, "read pdir_entry: %s\n", kvm_geterr(kd));
        return 0;
    }

    ptab_pa = (pdir_entry & 0xfffff000);  
    if (kvm_read(kd, ptab_pa + ptab_idx * sizeof(ptab_entry), &ptab_entry, sizeof(ptab_entry)) != sizeof(ptab_entry)) {
		fprintf(stderr, "read ptab_pa: %s\n", kvm_geterr(kd));
        return 0;
    }
    if (!(ptab_entry)) {  
		fprintf(stderr, "read ptab_entry: %s\n", kvm_geterr(kd));
        return 0;
    }

    unsigned long addr = (ptab_entry & 0xfffff000) | (vaddr & PAGE_MASK);
	
	char data[0x100]= {0};
	
	if(kvm_read(kd, addr, data, sizeof(data)) != sizeof(data)){
		fprintf(stderr, "read data: %s\n", kvm_geterr(kd));
	}
	
	printf("read data:%s\r\n",data);
	return addr;
	
}





int writeProcesData(pid_t target_pid, char *vaddr,char * value) {

    vaddr_t target_vaddr = (vaddr_t)vaddr;
    unsigned long new_value = (unsigned long)value;
    char errbuf[1024];
	
	target_pid = getpid();


    kvm_t *kd = kvm_open(NULL, NULL, NULL, O_RDWR, errbuf);
    if (kd == NULL) {
        fprintf(stderr, "kvm_open failed: %s\n", errbuf);
        return 1;
    }

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

/*
    struct vm_map vmap;
    if (kvm_read(kd, (unsigned long)&vmspace.vm_map, (void*)&vmap, sizeof(vmap)) != sizeof(vmap)) {
        fprintf(stderr, "read vm_map error: %s\n", kvm_geterr(kd));
        kvm_close(kd);
        return 1;
    }
	*/

/*
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
        fprintf(stderr, "address:0x%lx can not be written\n", target_vaddr);
        kvm_close(kd);
        return 1;
    }
	*/

	struct pmap *pmap =vmspace.vm_map.pmap;
	fprintf(stderr, "pmap:%x\n", pmap);
	

	
	char * data = "mytest value\r\n";
    paddr_t phys_addr = virt_to_phys(kd, pmap, data);
    if (phys_addr == 0) {
        fprintf(stderr, "virt_to_phys error\n");
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
