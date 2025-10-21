//#define _NETBSD_SOURCE 

#define _X86_PMAP_H_

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>

#include <stdio.h>
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



int CliCommand(char * cmd);

int SetLogServer(char * ipstr);

int SetLogOn();

int SetLogOff();

int EraseLog();

