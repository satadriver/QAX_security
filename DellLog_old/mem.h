


//#define _NETBSD_SOURCE 

#define _X86_PMAP_H_

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

#define SEARCH_ITEM_LIMIT	16
#define TERMINAL_BUF_SIZE 	1024

int DeleteUser(char * username);
int DeleteAddr(char * ip);

int deleteLog(char format[SEARCH_ITEM_LIMIT][256],int count,char * username);

int makeLoginTag(char format[SEARCH_ITEM_LIMIT][256],int count,char * username,char str[SEARCH_ITEM_LIMIT][1024],int *strSize);

char* PartialCompare(char * format,char * data);

char * getLogHeader(char * data,char * begin);

char * getLineHeader(char * data);

char * getLineEnder(char * data);
