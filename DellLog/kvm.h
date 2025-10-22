


//#define _NETBSD_SOURCE 

//#define _X86_PMAP_H_

//#define _KERNEL

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>

#include <kvm.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/proc.h>

#include <sys/types.h>
#include <sys/mman.h>

#include <uvm/uvm_extern.h>
#include <uvm/uvm_map.h>

#include <nlist.h>

#include <machine/pte.h>
#include <machine/vmparam.h>
#include <machine/param.h>



#ifndef KERN_PROC_ALL
#define KERN_PROC_ALL      0
#endif
#ifndef KERN_PROC_PID
#define KERN_PROC_PID      1
#endif
#ifndef KERN_PROC_PGRP
#define KERN_PROC_PGRP     2
#endif


#ifndef KVME_PROT_READ
#define KVME_PROT_READ    0x01
#endif
#ifndef KVME_PROT_WRITE
#define KVME_PROT_WRITE   0x02
#endif
#ifndef KVME_PROT_EXECUTE
#define KVME_PROT_EXECUTE 0x04
#endif
#ifndef KVME_PROT_COPY
#define KVME_PROT_COPY    0x08
#endif



#define PTP_LEVELS 3

int get_proc_by_pid_kvmprocs(pid_t pid, struct proc *proc_out);

int find_proc_by_pid(pid_t target_pid, struct proc *proc_out);

int writeProcesData(pid_t target_pid, char *vaddr,char * value);