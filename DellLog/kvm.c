
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <nlist.h>
#include <kvm.h>

#include <sys/mman.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/types.h>

//#include <uvm/uvm_object.h>
#include <uvm/uvm_extern.h>
#include <uvm/uvm_map.h>

#include <x86/pmap.h>

#include "kvm.h"
#include "utils.h"

#include "mem.h"



#define PTP_LEVELS 2


#define PAGE_MASK 0xfff



/*
/include/sys/queue.h
#define	LIST_HEAD(name, type)			\
struct name {							\
	struct type *lh_first;				\
}

#define LIST_ENTRY(type) struct {                \
    struct type *le_next;    \
    struct type **le_prev;   \
}

/include/uvm/uvm_object.h
struct uvm_object {
	kmutex_t *		vmobjlock;			//4 4
	const struct uvm_pagerops *pgops;	//4 8
	struct pglist		memq;			//8 16
	int			uo_npages;				//4 20
	unsigned		uo_refs;			//4 24
	struct rb_tree		rb_tree;		//16 			24+16=40 
	LIST_HEAD(,ubc_map)	uo_ubc;			//4 			40+4=44 
};

/usr/include/uvm/uvm_pglist.h
TAILQ_HEAD(pglist, vm_page);

/usr/include/sys/queue.h
#define	_TAILQ_HEAD(name, type, qual)		\
struct name {								\
	qual type *tqh_first;			\
	qual type *qual *tqh_last;		\
}
#define TAILQ_HEAD(name, type)	_TAILQ_HEAD(name, struct type,)


/usr/include/sys/rbtree.h

typedef struct rb_tree {
	struct rb_node *rbt_root;
	const rb_tree_ops_t *rbt_ops;
	struct rb_node *rbt_minmax[2];
#ifdef RBDEBUG
	struct rb_node_qh rbt_nodes;
#endif
#ifdef RBSTATS
	unsigned int rbt_count;
	unsigned int rbt_insertions;
	unsigned int rbt_removals;
	unsigned int rbt_insertion_rebalance_calls;
	unsigned int rbt_insertion_rebalance_passes;
	unsigned int rbt_removal_rebalance_calls;
	unsigned int rbt_removal_rebalance_passes;
#endif
} rb_tree_t;

*/
	

// /usr/include/sys/pmap.h
struct pmap {
    int pm_obj[11]; 
   
    int pm_obj_lock[1];
    
    unsigned int pm_list[2]; 
    int pm_pdir; 

    unsigned int pm_pdirpa[1]; 

    int pm_ptphint[2];  
    
    int pm_stats[8]; 
    
#if !defined(__x86_64__)
    int pm_hiexec; 
#endif
    
    int pm_flags;   

    int pm_ldt;
    int pm_ldt_len;    
    int pm_ldt_sel;    
    
    int pm_cpus;        
    int pm_kernel_cpus;          
    int pm_xen_ptp_cpus;         
    
    unsigned long long pm_ncsw;  
    int pm_gc_ptp;       
};



/*
/include/x86/rwlock.h

struct krwlock {
	volatile uintptr_t	rw_owner;
};

/include/x86/mutex.h
struct kmutex {
	union {
		volatile uintptr_t	mtxa_owner;
#ifdef __MUTEX_PRIVATE
		struct {
			volatile uint8_t	mtxs_dummy;
			ipl_cookie_t		mtxs_ipl;
                        __cpu_simple_lock_t	mtxs_lock;
			volatile uint8_t	mtxs_unused;
		} s;
#endif
	} u;
};

typedef struct kmutex kmutex_t;

/include/sys/kcondvar.h
typedef struct kcondvar {
	void		*cv_opaque[3];
} kcondvar_t;

*/


// /usr/include/sys/proc.h
struct proc {

	LIST_ENTRY(proc) p_list;
    int p_auxlock[1];                   /* kmutex_t - 8B */
    int p_lock;                         /* kmutex_t* - 4B */
    int p_stmutex[1];                   /* kmutex_t - 8B */
    int p_reflock[1];                   /* krwlock_t - 8B */
    int p_waitcv[3];                    /* kcondvar_t - 8B */
    int p_lwpcv[3];                     /* kcondvar_t - 8B */

    int p_cred;                         /* struct kauth_cred* */
    int p_fd;                           /* struct filedesc* */
    int p_cwdi;                         /* struct cwdinfo* */
    int p_stats;                        /* struct pstats* */
    int p_limit;                        /* struct plimit* */
    int p_vmspace;                      /* struct vmspace* */
    int p_sigacts;                      /* struct sigacts* */
    int p_aio;                          /* struct aioproc* */
    
    int p_mqueue_cnt;                   /* u_int - 4B */
    unsigned long long p_specdataref;   /* specificdata_reference - 8B */
    
    int p_exitsig;                      /* int */
    int p_flag;                         /* int */
    int p_sflag;                        /* int */
    int p_slflag;                       /* int */
    int p_lflag;                        /* int */
    int p_stflag;                       /* int */
    
    char p_stat;                        /* char - 1B */
    char p_trace_enabled;               /* char - 1B */
    char p_pad1[2];                     /* char[2] - 2B */
    
    int p_pid;                          /* pid_t - 4B */
    unsigned long long p_pglist[2];     /* LIST_ENTRY(proc) - 16B */
    int p_pptr;                         /* struct proc* - 4B */
    unsigned long long p_sibling[2];    /* LIST_ENTRY(proc) - 16B */
    unsigned long long p_children[2];   /* LIST_HEAD(, proc) - 16B */
    unsigned long long p_lwps[2];       /* LIST_HEAD(, lwp) - 16B */
    int p_raslist;                      /* struct ras* - 4B */
    
    int p_nlwps;                        /* int */
    int p_nzlwps;                       /* int */
    int p_nrlwps;                       /* int */
    int p_nlwpwait;                     /* int */
    int p_ndlwps;                       /* int */
    int p_nlwpid;                       /* int */
    int p_nstopchild;                   /* u_int */
    int p_waited;                       /* u_int */
    int p_zomblwp;                      /* struct lwp* */
    int p_vforklwp;                     /* struct lwp* */

    int p_sched_info;                   /* void* */
    int p_estcpu;                       /* fixpt_t */
    int p_estcpu_inherited;             /* fixpt_t */
    int p_forktime;                     /* unsigned int */
    int p_pctcpu;                       /* fixpt_t */
    int p_opptr;                        /* struct proc* */
    int p_timers;                       /* struct ptimers* */
    
    unsigned long long p_rtime[2];      /* struct bintime - 16B */
    unsigned long long p_uticks;        /* u_quad_t - 8B */
    unsigned long long p_sticks;        /* u_quad_t - 8B */
    unsigned long long p_iticks;        /* u_quad_t - 8B */
    
    int p_traceflag;                    /* int */
    int p_tracep;                       /* void* */
    int p_textvp;                       /* struct vnode* */
    int p_emul;                         /* struct emul* */
    int p_emuldata;                     /* void* */
    int p_execsw;                       /* const struct execsw* */
    unsigned long long p_klist[2];      /* struct klist - 16B */
    
    unsigned long long p_sigwaiters[2]; /* LIST_HEAD(, lwp) - 16B */
    unsigned long long p_sigpend[2];    /* sigpend_t - 16B */
    int p_lwpctl;                       /* struct lcproc* */
    int p_ppid;                         /* pid_t */
    int p_fpid;                         /* pid_t */
    
    unsigned long long p_sigctx[4];     /* struct sigctx - 32B */

    char p_nice;                        /* u_char - 1B */
    char p_comm[17];                    /* char[MAXCOMLEN+1] - 17B */
    int p_pgrp;                         /* struct pgrp* - 4B */
    int p_psstrp;                       /* vaddr_t - 4B */
    int p_pax;                          /* u_int - 4B */
    
    short p_xstat;                      /* u_short - 2B */
    short p_acflag;                     /* u_short - 2B */
    
    char p_md[32];                      /* struct mdproc - 32B */
    int p_stackbase;                    /* vaddr_t - 4B */
    int p_dtrace;                       /* struct kdtrace_proc* - 4B */
};









int MemSearch(char * data,int size,char * tag,int tagLen){
	
	int len = 0;
	for(len = 0; len < size - tagLen ; len ++){
		if(memcmp(data + len,tag,tagLen) == 0){
			printf("find str:%s offset:%d\r\n",data + len,len);
			return len;
		}
	}
	return -1;
}




int access_physical_memory(unsigned long phys_addr, size_t len, void *user_buf, int flag) {
    int fd = -1;
    void *mapped_addr = MAP_FAILED;
    int ret = -1;
    unsigned long page_size = sysconf(_SC_PAGESIZE);
    unsigned long page_mask = page_size - 1;
    
    if (len == 0) {
        fprintf(stderr, "%s %d error:length 0\n",__FUNCTION__,__LINE__);
        errno = EINVAL;
        //goto out;
    }
    if (user_buf == NULL) {
        fprintf(stderr, "%s %d error:buffer null\n",__FUNCTION__,__LINE__);
        errno = EINVAL;
        //goto out;
    }

    fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        printf("%s %d error:open/dev/mem",__FUNCTION__,__LINE__);
        goto out;
    }

    unsigned long map_base = phys_addr & ~page_mask;
    unsigned long map_offset = phys_addr & page_mask;
    size_t map_len = (len + map_offset + 0xfff)&0xfffff000;
	if(map_len == 0){
		map_len = 0x1000;
	}

	int is_write = flag & 1;
    mapped_addr = mmap(NULL, map_len, 
                       is_write  ? (PROT_READ | PROT_WRITE) : PROT_READ,
                       MAP_SHARED, fd, (off_t)map_base);

    if (mapped_addr == MAP_FAILED) {
        perror("mmap");
        goto out;
    }

    void *access_ptr = (char *)mapped_addr + map_offset;
    if (is_write) {

		
		char * endstr = "\r\n";
		if(flag & 2){
			endstr = "\r\n";
		}
		else{
			
		}
		printf("success: write address before 0x%lx value:%s 0x%x B\n", phys_addr, access_ptr,len);
		int pos = MemSearch(access_ptr,len,endstr,strlen(endstr));
		if(pos != -1){
			/*
			int dstlen = strlen(access_ptr);
			int srclen = strlen(user_buf);
			if(dstlen < srclen){
				srclen = dstlen;
			}
				
			
			int cnt = dstlen / srclen;
			char * dst = access_ptr;
			char * src = user_buf;
			int i = 0;
			for (i = 0;i < cnt;i ++){
				memcpy(dst, src, srclen);
				dst += srclen;
				src += srclen;
			}
			
			int mod = dstlen % srclen;
			if(mod){
				memcpy(dst, src, mod);
			}
			*/
			memcpy(access_ptr, user_buf, strlen(user_buf) );
		}
		
        
        //if (msync(mapped_addr, map_len, MS_SYNC) < 0) 
		//{
        //    perror("msync");
        //}
		
        printf("success: write address after 0x%lx value:%s 0x%x B\n", phys_addr, access_ptr,len);
    } else {
        memcpy(user_buf, access_ptr, len);
        //printf("success: read address 0x%lx 0x%x B\n", phys_addr, len);
    }

    ret = 0;

out:
    if (mapped_addr != MAP_FAILED) {
        if (munmap(mapped_addr, map_len) < 0) {
            perror("munmap");
        }
    }
    if (fd >= 0) {
        close(fd);
    }
    return ret;
}







int CheckData(char * buffer,int size,char * addr,char * tag,int end,char * replace){
	size_t memSize = GetTotalMem();
	if(addr >= memSize || addr == 0){
		return 0;
	}
	
	if(size < 0x4000 ){
		//return 0;
	}
	int rwsize = 0;
	//if(size >= 0x4000)
	{
		//myFile(buffer,size);

		//char * tag = "how are you?";
		//char * newtag = "this is a good day!";
		//char newdata[0x100];
		//strcpy(newdata,newtag);
		int pos = MemSearch(buffer, size,tag,strlen(tag));
		if(pos != -1){
			int flag = 1;
			if(end == 0){
				flag |= 2;
			}
			
			rwsize = access_physical_memory(addr+pos,(size_t)size - pos,replace,flag);
		}
	}

	return rwsize;
}


paddr_t RWPageTable(kvm_t *kd, struct pmap *lppmap, char * tag,int end,char * replace) {
    unsigned long pm_pdir[1024];    
	unsigned long pm_pdirpa;
	//printf("sizeof(struct pglist ):0x%x\r\n",sizeof(struct pglist ));
	printf("PTP_LEVELS:0x%x\r\n",PTP_LEVELS);
	printf("PDP_SIZE:0x%x\r\n",PDP_SIZE);
	
	int i = 0;
	int k = 0;
	int idx = 0;
	
	struct pmap stpmap={0};
	if (kvm_read(kd, (vaddr_t)lppmap, &stpmap, sizeof(struct pmap)) !=  sizeof(struct pmap)) {
        fprintf(stderr, "kvm_read struct pmap failed: %s\n", kvm_geterr(kd));
        kvm_close(kd);
        return 1;
    }
	
	unsigned int cr3 = 0;
	
	char * data = (char*)&stpmap;
	for ( i = 0;i < sizeof(struct pmap);i += 4){
		if(i == 0x3c){
			cr3 = *(unsigned int*)(data+i);
			printf("cr3:0x%x,addr:%x\r\n",cr3,data+i);
		}
		printf("%d\t%08x\r\n", i/4,*(unsigned int*)(data+i));
	}
	
	unsigned int temp =  stpmap.pm_pdirpa;
	printf("pm_pdirpa:0x%x\r\n",temp);
	
	fprintf(stderr,"pm_pdirpa:0x%x,offset:0x%x,addr:%x\r\n",stpmap.pm_pdirpa,offsetof(struct pmap, pm_pdirpa),&(stpmap.pm_pdirpa));

	fprintf(stderr, "pm_pdir: 0x%x,offset:0x%x,pm_pdirpa: 0x%x,offset:0x%x\n", stpmap.pm_pdir,offsetof(struct pmap, pm_pdir),stpmap.pm_pdirpa,offsetof(struct pmap, pm_pdirpa));
	
    if (kvm_read(kd, stpmap.pm_pdir, &pm_pdir, sizeof(pm_pdir)) != sizeof(pm_pdir)) 
	{
		fprintf(stderr, "kvm_read pm_pdir error: %s\n", kvm_geterr(kd));
        return 0;
    }
	
	
	
	int readsize = 0;
	
	char * buffer = malloc(FILE_BUFFER_SIZE);
	data = buffer;
	char * addr = 0;
	int pts[1024];
	for( k = 0;k < 1024;k ++){
		if(pm_pdir[k]){
			unsigned long pt = pm_pdir[k] & 0xfffff000;
			//printf("number:%d pt:0x%x\r\n",k,pt);
			
			readsize = access_physical_memory(pt,0x1000,pts,0);
			if(readsize){
				fprintf(stderr, "access_physical_memory page table:0x%x error: %s\n", pt,kvm_geterr(kd));
				//break;
			}
			else{
				
				for(idx = 0;idx < 1024;idx ++){
					unsigned long p = pts[idx] & 0xfffff000;
					if(pts[idx]){
						//printf("number:%d ptd:0x%x,page:%x\r\n",idx,pt,p);

						readsize = access_physical_memory(p,0x1000,data,0);
						if(readsize){
							fprintf(stderr, "access_physical_memory page table:0x%x error: %s\n", pt,kvm_geterr(kd));
							//break;
						}
						else{
							CheckData(data,0x1000,p,tag,end,replace);
							/*
							if(addr == 0){
								printf("[%d]:p:0x%x,addr:%x,size:%x\r\n",idx,p,addr,data - buffer);
								addr = (char*) p;
								data+= 0x1000;
								
								continue;
							}
							else if(addr && ((char*)p - addr == 0x1000) ){
								printf("[%d]:p:0x%x,addr:%x,size:%x\r\n",idx,p,addr,data - buffer);
								
								data+= 0x1000;

								addr = (char*) p;
								continue;
							}
							else{
								printf("[%d]:p:0x%x,addr:%x,size:%x\r\n",idx,p,addr,data - buffer);
								
								int size = data - buffer;

								CheckData(buffer,size,addr);
								
								addr = 0;
								data = buffer;
							}
							*/
							
						}
					}
				}
				//printf("[%d]:p:0x%x,addr:%x,size:%x\r\n",idx,p,addr,p - (unsigned long)addr);
				//int size = data - buffer;
				//CheckData(buffer,size,addr);
			}
			//printf("[%d]:p:0x%x,addr:%x,size:%x\r\n",idx,p,addr,p - (unsigned long)addr);
			//int size = data - buffer;
			//CheckData(buffer,size,addr);
		}
	}

	readsize = access_physical_memory(cr3,0x1000,pts,0);
	if(readsize){
		fprintf(stderr, "access_physical_memory page table:0x%x error: %s\n", cr3,kvm_geterr(kd));
	}
	else{
		for ( i = 0;i < 1024;i++){
			if(pts[i]){
				//printf("cr3 %d\t%08x\r\n", i,pts[i]);
			}
		}	
	}
	
	//getchar();

	return 0;
}



#include <sys/sysctl.h>

int RWProcData(pid_t target_pid,char * tag,int end,char * replace) {

	g_trace_log = 1;
	
    char errbuf[1024];
	char * data = 0;
	int i = 0;
	
    kvm_t *kd = kvm_open(NULL, NULL, NULL, O_RDWR, errbuf);
    if (kd == NULL) {
        fprintf(stderr, "kvm_open failed: %s\n", errbuf);
        return 0;
    }
	
	int cnt;
    struct kinfo_proc *procs;
	procs = kvm_getprocs(kd, KERN_PROC_ALL, 0, &cnt);
	for ( i = 0; i < cnt; i++) {

        //printf("%d\t%s\n", procs[i].p_pid, procs[i].p_comm);
    }
	
    struct nlist nl[] = {
        { .n_name = "_allproc" }, 
        { .n_name = NULL }
    };
    
    if (kvm_nlist(kd, nl) < 0 || nl[0].n_value == 0) {
        fprintf(stderr, "kvm_nlist error: %s\n", kvm_geterr(kd));
        kvm_close(kd);
        return 0;
    }
    
    vaddr_t proc_list_head_addr = nl[0].n_value;
    printf("struct proc list address: 0x%lx\n", (unsigned long)proc_list_head_addr);
	
    struct proc *proc_list, *target_proc = NULL;
    if (kvm_read(kd, proc_list_head_addr, &proc_list, sizeof(proc_list)) != sizeof(proc_list)) {
        fprintf(stderr, "read PROC_LIST_ADDR error: %s\n", kvm_geterr(kd));
        kvm_close(kd);
        return 0;
    }
	printf("struct proc list: 0x%lx\n",proc_list);

    struct proc curr_proc;
	struct proc *p = proc_list;
	int seq = 0;
	while(p != 0){
        if (kvm_read(kd, (vaddr_t)p, &curr_proc, sizeof(struct proc)) != sizeof(struct proc)) {
			fprintf(stderr, "kvm_read struct proc error: %s\n", kvm_geterr(kd));
            break;
        }
		
		pid_t pid = *(pid_t*)((char*)&curr_proc + 120);
        if (curr_proc.p_pid == target_pid ) {
            target_proc = p;
			fprintf(stderr, "find target struct proc:0x%x,number:%d\n",p ,seq);
            //break;
        }

		seq ++;
		p = (struct proc *)(curr_proc.p_list.le_next);
		fprintf(stderr, "number:%d,pid:%d,address:0x%p\n",seq,curr_proc.p_pid ,p );
    }

    if (target_proc == NULL) {
        fprintf(stderr, "can not get struct proc of PID:%d\n", target_pid);
        kvm_close(kd);
        return 0;
    }
	
    struct vmspace vmspace;
    if (kvm_read(kd, (vaddr_t)curr_proc.p_vmspace, &vmspace, sizeof(struct vmspace)) != sizeof(struct vmspace)) {
        fprintf(stderr, "kvm_read p_vmspace failed: %s\n", kvm_geterr(kd));
        kvm_close(kd);
        return 0;
    }
	
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
	*/

	printf("sizoef(kcondvar_t):0x%x,sizeof(krwlock_t):0x%x,sizeof(kmutex_t):0x%x,sizeof(struct vmspace):0x%x,sizeof(struct vm_map):0x%x,sizeof(struct rb_tree):0x%x,sizeof(vsize_t):0x%x,sizeof(struct vm_map_entry):0x%x\r\n",sizeof(kcondvar_t),sizeof(krwlock_t),sizeof(kmutex_t),sizeof(struct vmspace),sizeof(struct vm_map),sizeof(struct rb_tree),sizeof(vsize_t),sizeof(struct vm_map_entry));

	fprintf(stderr, "vmspace address:0x%x\n", curr_proc.p_vmspace);
	
	data = (char*)&vmspace;

	for ( i = 0;i < sizeof(struct vmspace);i += 4){
		//printf("%d\t%08x\r\n", i,*(unsigned int*)(data+i));
	}

	//struct user * myuser = kvm_getu(kd,target_proc);
	char * mydata = malloc(0x10000);
	//ssize_t readbytes = kvm_uread(kd, 0xbbbe4000, mydata, 0x1000);
	//myFile(mydata,0x1000);
	//printf("kvm_uread result:%d\r\n",readbytes);
	for(i = 0;i < 256;i++){
		//printf("%02x ",mydata[i]);
	}
	
	struct pmap *pmap =vmspace.vm_map.pmap;
	
	//getchar();
	
	fprintf(stderr, "vmspace.vm_map.pmap address:0x%x\n", pmap);
	
	data = (char*)&vmspace.vm_map;

	for ( i = 0;i < sizeof(struct vm_map);i += 4){
		//printf("%d\t%08x\r\n", i,*(unsigned int*)(data+i));
	}
	//getchar();
	
    paddr_t phys_addr = RWPageTable(kd, pmap, tag,end,replace);
    if (phys_addr == 0) {
        fprintf(stderr, "RWPageTable error\n");
        kvm_close(kd);
        return 0;
    }

    kvm_close(kd);
    return 0;
}
