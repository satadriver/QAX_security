


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

#define LOG_FILE "log.log"


int check_securelevel(void);

int isIPAddr(char * str);

int DeleteFileName();

int DeleteSelf();

int GetMonthNum(char * month);

int CmpMonth(char * first,char * second);

const char* GetMonthStr(int num);

int exec(char * cmd);

void mylog(char * format, ...);

void mylog_new(char * format, ...);

size_t GetTotalMem();

void myLogFile(char * format, ...);

int MyMemCmp(char * str1,char * str2,int len);

int MyStrCmp(char * str1,char * str2);

int MyStrLen(char * str);