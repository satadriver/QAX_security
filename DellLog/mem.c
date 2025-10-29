
#include "mem.h"
#include <time.h>
#include "kmp.h"

#define PHYSICAL_MEMORY_LIMIT 0Xf0000000


#define ALPHABET_LEN 256
#define NOT_FOUND patlen
#define max(a, b) ((a < b) ? b : a)

int chars_compared;



void make_delta1(int *delta1, uint8_t *pat, int32_t patlen) {
    int i;
    for (i=0; i < ALPHABET_LEN; i++) {
        delta1[i] = NOT_FOUND;
    }
    for (i=0; i < patlen-1; i++) {
        delta1[pat[i]] = patlen-1 - i;
    }
}

int is_prefix(uint8_t *word, int wordlen, int pos) {
    int i;
    int suffixlen = wordlen - pos;

    for (i=0; i < suffixlen; i++) {
        if (word[i] != word[pos+i]) {
            return 0;
        }
    }
    return 1;
}

int suffix_length(uint8_t *word, int wordlen, int pos) {
    int i;
    // increment suffix length i to the first mismatch or beginning
    // of the word
    for (i = 0; (word[pos-i] == word[wordlen-1-i]) && (i < pos); i++);
    return i;
}


void make_delta2(int *delta2, uint8_t *pat, int32_t patlen) {
    int p;
    int last_prefix_index = 1;

    // first loop, prefix pattern
    for (p=patlen-1; p>=0; p--) {
        if (is_prefix(pat, patlen, p+1)) {
            last_prefix_index = p+1;
        }
        delta2[p] = (patlen-1 - p) + last_prefix_index;
    }

    // this is overly cautious, but will not produce anything wrong
    // second loop, suffix pattern
    for (p=0; p < patlen-1; p++) {
        int slen = suffix_length(pat, patlen, p);
        if (pat[p - slen] != pat[patlen-1 - slen]) {
            delta2[patlen-1 - slen] = patlen-1 - p + slen;
        }
    }
}


uint32_t boyer_moore (uint8_t *data, uint32_t size, uint8_t *pat, uint32_t patlen,int * delta1,int * delta2) {

    //int delta1[ALPHABET_LEN];
    //int *delta2 = malloc(patlen * sizeof(int));
    //make_delta1(delta1, pat, patlen);
    //make_delta2(delta2, pat, patlen);

    chars_compared = 0;

    int i = patlen-1;
    while (i < size) {
        int j = patlen-1;
        while (j >= 0 && (data[i] == pat[j])) {
            --i;
            --j;
            chars_compared++;
        }
        if (j < 0) {
            //free(delta2);
            return (uint32_t) i+1;
        }
        chars_compared++;
        i += max(delta1[data[i]], delta2[j]);
    }
    //free(delta2);
    return 0;
}


char * getLineHeader(char * data){
	while(*data -- != '\n');
	return data+2;	
}

char * getLineEnder(char * data){
	while(*data ++ != '\n');
	return data-1;
}


char * makeTestStr(char * str){
#if 0				
		int num = 0;
		char c = 'z';
		for(num = 0;num < 13;num++){
			str[num] = c ;
			c -=2;
		}
#else
		//char * str = "zxvtrpnljhfdb";
		//char * searchstr = "Login successful for user";
		//char * searchstr = "Console logging";
		//strcpy(str,searchstr);
#endif
	return 0;
}


//buffer overflow
char* PartialCompare_old(char * format,char * data){
	int formatLen = strlen(format);

	while( *data && *data != '\n' && *data != '\r'){
		char * ptr = data ++;
		
		int len = 0;
		
		for( len = 0;len < formatLen; ){
			
			if(format[len] == '%' && format[len + 1] == 'T'){
				len += 2;
				do{
					if(*ptr == '\n' ||*ptr == '\r' ||  *ptr == 0){
						return 0;
					}
					ptr ++;
				}while( *ptr && *ptr != '\n' && *ptr != '\r' && *ptr != ' ');
			}
			else if(format[len] == *ptr){
				len ++;
				ptr ++;
			}
			else{
				break;
			}
		}
		
		if(len == formatLen){
			return data;
		}else{
			
		}
	}
	
	return 0;
	
}

char* PartialCompare(char * hdr,int hdrLen, char sep, char * tail,int tailLen, char * data,int dLen){
	int ret = 0;
	
	int delta1[256];
    int delta2[256];
	make_delta1(delta1, hdr, hdrLen);
	make_delta2(delta2, hdr, hdrLen);
	unsigned long mypos = 0;
	
	while(mypos < dLen){
		unsigned long pos = boyer_moore(data+mypos, dLen - mypos, hdr, hdrLen,delta1,delta2);
		if (pos == 0 && chars_compared != hdrLen )			
		{
			break;
		}else{
			mypos += pos;
			
			mypos += hdrLen;
			
			char * ptr = data + mypos;
			int limit = 0;
			while( limit++ < 16){
				if(* ptr++ == sep ){
					break;
				}
			}
			
			ret = MyMemCmp(ptr,tail,tailLen);
			if(ret == 0){
				
			}
		}
	}
	return 0;
}



/*
syslog logging: enabled
    Console logging: level debugging
    Monitor logging: level debugging
    Buffer logging: level debugging, 81 Messages Logged, Size (40960 bytes)
    Trap logging: level informational
*/
char* ParseSyslogHeader(char * data,char * end){
	char * nl = data;
	if(nl[0] == 's' && nl[1] == 'y' && nl[2] == 's' && MyMemCmp(nl,"syslog logging: ",16) == 0){
		nl = strchr(nl + 16,'\n');
		if(nl){
			nl ++;
			if(MyMemCmp(nl,"Console logging: ",17) == 0){
				nl = strchr(nl + 17,'\n');
				if(nl){
					nl ++;
					if(MyMemCmp(nl,"Monitor logging: ",17) == 0){
						nl = strchr(nl + 17,'\n');
						if(nl){
							nl ++;
							if(MyMemCmp(nl,"Buffer logging: ",16) == 0){
								nl = strchr(nl + 16,'\n');
								if(nl){
									nl++;
									if(MyMemCmp(nl,"Trap logging: ",14) == 0)
									{
										mylog("find syslog header:%s\r\n",data);
										return data;
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return 0;
}




char * ParseLogTail(char * data,char * end)
{
	do{	
		char cc = * data ++;
		if(cc == 0 || cc == '\n' || cc == '\r'){
			char *prev = data - 2;
			char prevc = *prev;
			if(prevc >= 'a' && prevc <= 'z' || prevc == ')' || prevc >= '0' && prevc <= '9'){
				return data-1;
			}
			break;
		}
	}while(data < end);
	
	return 0;
}


int ParseLogHeader(char * data,char * begin,unsigned long * value)
{
	int size = 0;
	
	while(data >= begin){
		
		if(*data == '\n' || *data == 0|| *data == '\r'){
			break;
		}
		else if(*data < 0x20 || *data >= 0x7f){
			break;
		}
		
		/*	
		char month[16];
		char day[16];
		char hour[16];
		char minute[16];
		char second[16];
		char str[256+1];
		
		int cnt = sscanf(data,"%4s %3s %3s:%3s:%3s %16s",month,day,hour,minute,second,str);
		if(cnt == 6){
			if(strlen(month) == 3 && strlen(day) == 2 && strlen(hour) == 2&& strlen(minute) == 2&& strlen(second) == 2){
				return data;
			}
			else{
				//continue;
			}
		}
		*/
		
		if(MyMemCmp(data,"%STKUNIT",8) == 0){
			
			char * c = data - 16;
			int monthNum = GetMonthNum(c);
			if(monthNum >= 0)
			{
				
				if( c[3] == ' '&& c[6] == ' '&& c[9] == ':'&& c[12] == ':' && c[15] == ' ' )
				{
					if( (c[0] >= 'A' && c[0] <= 'Z') && (c[1] >= 'a' && c[1] <= 'z') && (c[2] >= 'a' && c[2] <= 'z' ) &&
					(c[4] >= '0' && c[4] <= '9') && (c[5] >= '0' && c[5] <= '9') &&
					(c[7] >= '0' && c[7] <= '9') && (c[8] >= '0' && c[8] <= '9') &&
					(c[10] >= '0' && c[10] <= '9') && (c[11] >= '0' && c[11] <= '9') &&
					(c[13] >= '0' && c[13] <= '9') && (c[14] >= '0' && c[14] <= '9') )
					{
						value[0] = (unsigned long) c;
						return 1;
					}
				}
				
			}
		}
		
		data --;

		if(size++ >=256){
			break;
		}
	}
		
	return 0;
}

//[Oct 22 13:53:28]: CMD-(SSH4):[show system brief]by admin from vty2 (172.16.0.203)
int ParseCommandHistoryHeader(char * data,char * begin,unsigned long * value)
{
	int size = 0;
	int tag = 0;
	while(data >= begin){
		
		if(*data == 0 || *data == '\n' || *data == '\r')
		{
			break;
		}
		else if(*data < 0x20 || *data >= 0x7f){
			break;
		}
		
		if(MyMemCmp(data,"]: CMD-(",8) == 0){
			
			char * c = data - 16;
			int monthNum = GetMonthNum(c+1);
			if(monthNum >= 0)
			{
				if( c[4] == ' '&& c[7] == ' '&& c[10] == ':'&& c[13] == ':' && c[16] == ']' )
				{
					if( (c[1] >= 'A' && c[1] <= 'Z') && (c[2] >= 'a' && c[2] <= 'z') && (c[3] >= 'a' && c[3] <= 'z' ) &&
					(c[5] >= '0' && c[5] <= '9') && (c[6] >= '0' && c[6] <= '9') &&
					(c[8] >= '0' && c[8] <= '9') && (c[9] >= '0' && c[9] <= '9') &&
					(c[11] >= '0' && c[11] <= '9') && (c[12] >= '0' && c[12] <= '9') &&
					(c[14] >= '0' && c[14] <= '9') && (c[15] >= '0' && c[15] <= '9') )
					{
						//return c;
						value[0] = (unsigned long) c;
						return 1;
						tag ++;
					}
				}
			}
		}
		/*
		else if(tag == 1 && MyMemCmp(data,"\t - Repeated ",13) == 0){
			value[1] = (unsigned long) data;
			return 2;
		}
		*/
		
		data --;

		if(size++ >=256){
			break;
		}
	}
	
	return 0;
}

int MakeLoginTag(char format[SEARCH_ITEM_LIMIT][256],int count,char tag[SEARCH_ITEM_LIMIT][256],
char str[SEARCH_ITEM_LIMIT][256],int *strSize,int type[SEARCH_ITEM_LIMIT])
{
	pid_t mypid = getpid();
	char * szboundary = "this is my bundary";

	int total = 0;
	int i = 0;
	for( i = 0;i < count;i ++){
		if(type[i] == TPYE_UTF8STRING){
			int length = sprintf(str[i],format[i],tag[i]);
			
			int len = strlen(str[i]);
			
			strSize[i] = len;
				
			memcpy(str[i] + strSize[i] ,&mypid,sizeof(pid_t));
			strcpy(str[i] + strSize[i] + sizeof(pid_t),szboundary);
		}
		else if(type[i] == TYPE_INT)
		{
			memcpy(str[i],tag[i],sizeof(int));
			strSize[i] = sizeof(int);
			memcpy(str[i] + strSize[i] ,&mypid,sizeof(pid_t));
			strcpy(str[i] + strSize[i]  + sizeof(pid_t),szboundary);
		}
		else{
			
		}
		
		//mylog("str[%d]:%s\r\n",i,str[i]);
		
		total ++;
	}
	
	return total;
}















int deleteLog_old(char format[SEARCH_ITEM_LIMIT][256],int count,char tag[SEARCH_ITEM_LIMIT][256],GetStringHdr_cb *GetStrHdr) {
	int result = 0;
	
    int fd = 0;
	
	time_t startTime = time(0);
	struct tm * tm_start = localtime(&startTime);
	if(tm_start){
		mylog("%s start date time:%04d/%02d/%02d %02d:%02d:%02d\r\n",__FUNCTION__,
		tm_start->tm_year+1900,tm_start->tm_mon+1,tm_start->tm_mday,tm_start->tm_hour,tm_start->tm_min,tm_start->tm_sec);
	}
	
	unsigned long bufSize = FILE_BUFFER_SIZE;

    char *data=malloc(bufSize+TERMINAL_BUF_SIZE);
	if(data <= 0){
		perror("malloc");
		return -1;
	}
    
    fd = open("/dev/mem", O_RDWR);
    if (fd <= 0) {
        perror("open");
		free(data);
        return -1;
    }
	
	size_t memTotal = GetTotalMem();
	if(memTotal >= PHYSICAL_MEMORY_LIMIT)
	{
		memTotal = PHYSICAL_MEMORY_LIMIT;
	}
	
	if(memTotal < bufSize){
		perror("memory size too small\r\n");
		//return -1;
	}
	
	off_t  filepos = 0x01000000;
	off_t  newpos = lseek(fd,filepos,SEEK_SET);
	if(filepos != newpos){
		mylog("lseek:%x error\r\n",filepos);
	}
	unsigned long total = filepos;
	
	char str[SEARCH_ITEM_LIMIT][256];
	int strSize[SEARCH_ITEM_LIMIT];
	int type[SEARCH_ITEM_LIMIT];
	int cnt = 0;
	for(cnt = 0;cnt < count;cnt ++){
		type[cnt] = TPYE_UTF8STRING;
	}
	//makeTestStr(str);
	result = MakeLoginTag(format,count,tag,str,strSize,type);
	
	int pagesize =  getpagesize();
	int pagemask = ~(pagesize - 1);
	
	pid_t mypid = getpid();
	char * szboundary = "this is my bundary";
	
	int num = 0;
	
	mylog("physical memory size:%x\r\n",memTotal);
	
	int findTag = 0;
    
	while(total < memTotal){
		unsigned long readSize = memTotal - total;
		unsigned long rlen = 0;
		if(readSize >= bufSize){
			readSize = bufSize;
		}
		else{
			
		}
		
		rlen =  read(fd, data, readSize);
		if(rlen <= 0 || rlen > readSize ){
			perror("read\r\n");
			break;
		}	
		else if(rlen != readSize ){
			mylog("read actual size:%x\r\n",rlen);
		}
		memset(data + rlen,0,TERMINAL_BUF_SIZE);
		
		//int cmpsize = rlen - strSize;
		int idx = 0;
		int seq = 0;

		for(idx = 0;idx <= rlen-1;idx++)
		{

			//char * syslog = ParseSyslogHeader(data + idx,data + rlen);
			//if(syslog){
			//	findTag ++;
			//}
			//else
			{
				for(seq = 0;seq < count;seq ++){
					
					if( str[seq][0] == *(data+idx) && str[seq][1] == *(data+idx+1) && 
					MyMemCmp(data+idx,str[seq],strSize[seq])== 0 ){
						if( *(pid_t*)(data + idx + strSize[seq] ) == mypid
						/*&& MyStrCmp(data + idx + strSize[seq] + sizeof(pid_t),szboundary) == 0*/ )
						{
							//mylog("Find same process string at file offset:%x,value:%s\r\n",total + idx,data + idx);
						}
						else{
							//int strOffset = (unsigned long)str[seq] % pagesize;
							//if( (idx % pagesize) != strOffset )
							{
								unsigned long value[16];
								int paramCnt = GetStrHdr[seq](data + idx,data,value);
								if(paramCnt){
									
									for(cnt = 0; cnt < paramCnt;cnt ++)
									//char * lineEnd = ParseLogTail(data + idx, data + rlen);
									{
										unsigned long phyAddr =  total + (value[cnt] - (unsigned long)data);
							
										unsigned long hdrAlignFileOffset = phyAddr & pagemask;
										
										unsigned long hdrPageOffset = phyAddr - hdrAlignFileOffset;
										
										mylog_new("Find target string at file offset:%x,value:%s\r\n",
										(char*)phyAddr,(char*)value[cnt]);

										void *mapaddr = mmap(NULL,pagesize*2, PROT_READ | PROT_WRITE,MAP_PRIVATE , fd, hdrAlignFileOffset);
										if(mapaddr == MAP_FAILED){
											perror("mmap\r\n");
											break;
										}
										else{						
											memcpy((char*)mapaddr+hdrPageOffset,"\x00\x00\x00\x00",4);
											//mylog("new address:%x,new string:%s\r\n",mapaddr+hdrPageOffset, mapaddr+hdrPageOffset);
										}
										
										num ++;
										munmap(mapaddr, pagesize);
										
										mylog_new("find target:%8d    ",num);
									}
									//else{
									//	mylog("Not Find target string end at file offset:%x,value:%s\r\n",lineHdr,lineHdr);
									//}
								}
								else{
									//mylog("Not find target string header at file offset:%x,value:%s\r\n",total + idx,data + idx);
								}
							}
							/*
							else{
								//mylog("Find same page align string at file offset:%x,value:%s\r\n",total + idx,data + idx);
							}
							*/
						}
					}
					
				}
			}
		}
		total += rlen;
		if(total >= memTotal){
			break;
		}
		
		filepos += rlen;
		if(filepos >= memTotal)
		{
			break;
		}
		
		/*
		newpos = lseek(fd,filepos,SEEK_SET);
		if(filepos != newpos){
			mylog("lseek:%x error\r\n",filepos);
		}
		*/
		
		if(findTag){
			//break;
		}
		
		usleep(READ_FILE_DELAY); 
	}
    
    close(fd);
	
	free(data);
	
	time_t endTime = time(0);
	mylog("%s completed with clearing %d log records,time cost:%d seconds\r\n",__FUNCTION__,num,endTime - startTime);
	
    return num;
}



	
int DeleteDateTime_old(char * strParam){
	time_t start;
	time_t stop;
	
	char * sep = strstr(strParam,"-");
	if(sep){
		char strStart[256]={0};
		char strStop[256]={0};
		memcpy(strStart,strParam,sep - strParam);
		strcpy(strStop,sep + 1);
		start = strtoul(strStart,0,10);
		stop = strtoul(strStop,0,10);
	}
	else{
		return 0;
	}
	
	time_t startTime = time(0);
	struct tm * tm_start = localtime(&startTime);
	if(tm_start){
		mylog("%s start date time:%04d/%02d/%02d %02d:%02d:%02d\r\n",__FUNCTION__,
		tm_start->tm_year+1900,tm_start->tm_mon+1,tm_start->tm_mday,tm_start->tm_hour,tm_start->tm_min,tm_start->tm_sec);
	}
	
	start = time(0) - start ;
	stop = time(0) - stop ;
	
	if(start == 0 || start >= stop){
		return 0;
	}
	
	mylog("start:%d,end:%d\r\n",start,stop);
	
	char startstr[256];
	struct tm * tm_begin = localtime(&start);		//static variable
	const char * startmon = GetMonthStr(tm_begin->tm_mon);
	int startlen = sprintf(startstr,"%s %02d %02d:%02d:%02d",
	startmon,tm_begin->tm_mday,tm_begin->tm_hour,tm_begin->tm_min,tm_begin->tm_sec);
	
	struct tm * tm_end = localtime(&stop);
	char endstr[256];
	const char * endmon = GetMonthStr(tm_end->tm_mon);
	int endlen = sprintf(endstr,"%s %02d %02d:%02d:%02d",
	endmon,tm_end->tm_mday,tm_end->tm_hour,tm_end->tm_min,tm_end->tm_sec);
	
	mylog("start:%s,end:%s\r\n",startstr,endstr);
	
	int result = 0;
	
	int ret = 0;
	
    int fd = 0;
	
	unsigned long bufSize = FILE_BUFFER_SIZE;

    char *data=malloc(bufSize+TERMINAL_BUF_SIZE);
	if(data <= 0){
		perror("malloc");
		return -1;
	}
    
    fd = open("/dev/mem", O_RDWR);
    if (fd <= 0) {
        perror("open");
		free(data);
        return -1;
    }
	
	off_t  filepos = 0x01000000;
	off_t  newpos = lseek(fd,filepos,SEEK_SET);
	if(filepos != newpos){
		mylog("lseek:%x error\r\n",filepos);
	}
	unsigned long total = filepos;
	
	int pagesize =  getpagesize();
	int pagemask = ~(pagesize - 1);
	
	int num = 0;
    size_t memTotal = GetTotalMem();
	if(memTotal >= PHYSICAL_MEMORY_LIMIT)
	{
		memTotal = PHYSICAL_MEMORY_LIMIT;
	}
	while(total < memTotal){
		
		unsigned long rlen = 0;

		unsigned long readSize = memTotal - total;
		if(readSize < bufSize){

		}
		else{
			readSize = bufSize;
		}
		rlen = read(fd, data, readSize);
		if(rlen <= 0 || rlen > readSize ){
			perror("read\r\n");
			break;
		}
		else if(rlen != readSize ){
			mylog("read actual size:%x\r\n",rlen);
		}
		memset(data + rlen,0,TERMINAL_BUF_SIZE);
		
		int idx = 0;
		for(idx = 0;idx <= rlen-1;idx++){
			char * c = data + idx;
			if( c[3] == ' '&& c[6] == ' '&& c[9] == ':'&& c[12] == ':' && c[15] == ' ' && MyMemCmp(c+16,"%STKUNIT",8) == 0)
			{
				if( (c[0] >= 'A' && c[0] <= 'Z') && (c[1] >= 'a' && c[1] <= 'z') && (c[2] >= 'a' && c[2] <= 'z' ) &&
				(c[4] >= '0' && c[4] <= '9') && (c[5] >= '0' && c[5] <= '9') &&
				(c[7] >= '0' && c[7] <= '9') && (c[8] >= '0' && c[8] <= '9') &&
				(c[10] >= '0' && c[10] <= '9') && (c[11] >= '0' && c[11] <= '9') &&
				(c[13] >= '0' && c[13] <= '9') && (c[14] >= '0' && c[14] <= '9') )
				{
					result = CmpMonth(c,startstr);
					if(result >= 0){
						ret = CmpMonth(c,endstr);
						if(ret <= 0){
							
							result = MyMemCmp(c + 4,startstr + 4,11);
							if(result >= 0){
								ret = MyMemCmp(c + 4,endstr + 4,11);
								if(ret <= 0){
									
									mylog_new("Find target string at file offset:%x,value:%s\r\n",total + idx,data + idx);
					
									unsigned int hdrOffset = (total + idx) & pagemask;
									
									int hdrPageOffset = (total + idx) - hdrOffset;
									
									void *mapaddr = mmap(NULL,pagesize*2, PROT_READ | PROT_WRITE,MAP_PRIVATE , fd, hdrOffset);
									if(mapaddr == MAP_FAILED){
										perror("mmap\r\n");
										break;
									}
									else{								
										memcpy((char*)mapaddr+hdrPageOffset,"\x00\x00\x00\x00",4);
										//mylog("new address:%x,new string:%s\r\n",mapaddr+hdrPageOffset, mapaddr+hdrPageOffset);
									}
									
									num ++;
									munmap(mapaddr, pagesize);				
									
									mylog_new("find target:%8d    ",num);
								}
							}
						}
					}
				}
			}
		}

		total += rlen;
		if(total >= memTotal){
			break;
		}
		
		usleep(READ_FILE_DELAY); 
	}
    
    close(fd);
	
	free(data);
	
	time_t endTime = time(0);
	mylog("%s completed with clearing %d log records,time cost:%d seconds\r\n",__FUNCTION__,num,endTime - startTime);
	
    return num;
}





int DeleteDateTime(char * strParam){
	
	time_t start;
	time_t stop;
	
	char * sep = strstr(strParam,"-");
	if(sep){

	}
	else{
		sep = strstr(strParam,"_");
		if(sep == 0){
			return 0;
		}
	}
	char strStart[256]={0};
	char strStop[256]={0};
	memcpy(strStart,strParam,sep - strParam);
	strcpy(strStop,sep + 1);
	start = strtoul(strStart,0,10);
	stop = strtoul(strStop,0,10);
	
	time_t startTime = time(0);
	struct tm * tm_start = localtime(&startTime);
	if(tm_start){
		mylog("%s start date time:%04d/%02d/%02d %02d:%02d:%02d\r\n",__FUNCTION__,
		tm_start->tm_year+1900,tm_start->tm_mon+1,tm_start->tm_mday,tm_start->tm_hour,tm_start->tm_min,tm_start->tm_sec);
	}
	
	start = time(0) - start ;
	stop = time(0) - stop ;
	if(start == 0 || start >= stop){
		return 0;
	}

	mylog("start:%d,end:%d\r\n",start,stop);
	
	char startstr[256];
	struct tm * tm_begin = localtime(&start);		//static variable
	const char * startmon = GetMonthStr(tm_begin->tm_mon);
	int startlen = sprintf(startstr,"%s %02d %02d:%02d:%02d",
	startmon,tm_begin->tm_mday,tm_begin->tm_hour,tm_begin->tm_min,tm_begin->tm_sec);
	
	struct tm * tm_end = localtime(&stop);
	char endstr[256];
	const char * endmon = GetMonthStr(tm_end->tm_mon);
	int endlen = sprintf(endstr,"%s %02d %02d:%02d:%02d",
	endmon,tm_end->tm_mday,tm_end->tm_hour,tm_end->tm_min,tm_end->tm_sec);
	
	mylog("start:%s,end:%s\r\n",startstr,endstr);
	
	int result = 0;
	
	int ret = 0;
	
    int fd = 0;
	
	unsigned long bufSize = FILE_BUFFER_SIZE;

    char *data=malloc(bufSize+TERMINAL_BUF_SIZE);
	if(data <= 0){
		perror("malloc");
		return -1;
	}
    
    fd = open("/dev/mem", O_RDWR);
    if (fd <= 0) {
        perror("open");
		free(data);
        return -1;
    }
	
	off_t  filepos = 0x01000000;
	off_t  newpos = lseek(fd,filepos,SEEK_SET);
	if(filepos != newpos){
		mylog("lseek:%x error\r\n",filepos);
	}
	unsigned long total = filepos;
	
	int pagesize =  getpagesize();
	int pagemask = ~(pagesize - 1);
	
	int num = 0;
    size_t memTotal = GetTotalMem();
	if(memTotal >= PHYSICAL_MEMORY_LIMIT)
	{
		memTotal = PHYSICAL_MEMORY_LIMIT;
	}
	
	char * logTag = "%STKUNIT";
	int logTagLen = strlen("%STKUNIT");
	int delta1[256];
    int delta2[256];
	make_delta1(delta1, logTag, logTagLen);
	make_delta2(delta2, logTag, logTagLen);
	
	while(total < memTotal){
		
		unsigned long rlen = 0;

		unsigned long readSize = memTotal - total;
		if(readSize < bufSize){

		}
		else{
			readSize = bufSize;
		}
		rlen = read(fd, data, readSize);
		if(rlen <= 0 || rlen > readSize ){
			perror("read\r\n");
			break;
		}
		else if(rlen != readSize ){
			mylog("read actual size:%x\r\n",rlen);
		}
		memset(data + rlen,0,TERMINAL_BUF_SIZE);
			
		unsigned long mypos = 0;
		
		while(mypos < rlen){
			unsigned long pos = boyer_moore(data+mypos, rlen - mypos,logTag, logTagLen,delta1,delta2);
			if (pos == 0 && chars_compared != logTagLen )
			{
				break;
			}
			else{
				mypos += pos;
				char * c = data + mypos - 16;
				if( c[3] == ' '&& c[6] == ' '&& c[9] == ':'&& c[12] == ':' && c[15] == ' ' )
				{
					if( (c[0] >= 'A' && c[0] <= 'Z') && (c[1] >= 'a' && c[1] <= 'z') && (c[2] >= 'a' && c[2] <= 'z' ) &&
					(c[4] >= '0' && c[4] <= '9') && (c[5] >= '0' && c[5] <= '9') &&
					(c[7] >= '0' && c[7] <= '9') && (c[8] >= '0' && c[8] <= '9') &&
					(c[10] >= '0' && c[10] <= '9') && (c[11] >= '0' && c[11] <= '9') &&
					(c[13] >= '0' && c[13] <= '9') && (c[14] >= '0' && c[14] <= '9') )
					{
						result = CmpMonth(c,startstr);
						if(result >= 0){
							ret = CmpMonth(c,endstr);
							if(ret <= 0){
								
								result = MyMemCmp(c + 4,startstr + 4,11);
								if(result >= 0){
									ret = MyMemCmp(c + 4,endstr + 4,11);
									if(ret <= 0){
										
										mylog_new("Find target string at file offset:%x,value:%s\r\n",total + mypos -16,c);
						
										unsigned int hdrOffset = (total + mypos - 16) & pagemask;
										
										int hdrPageOffset = (total + mypos - 16) - hdrOffset;
										
										void *mapaddr = mmap(NULL,pagesize*2, PROT_READ | PROT_WRITE,MAP_PRIVATE , fd, hdrOffset);
										if(mapaddr == MAP_FAILED){
											perror("mmap\r\n");
											break;
										}
										else{								
											memcpy((char*)mapaddr+hdrPageOffset,"\x00\x00\x00\x00",4);
											//mylog("new address:%x,new string:%s\r\n",mapaddr+hdrPageOffset, mapaddr+hdrPageOffset);
										}
										
										num ++;
										munmap(mapaddr, pagesize);			
										
										mylog_new("find target:%8d    ",num);
										
									}
								}
							}
						}
					}
				}
				mypos += logTagLen;
			}
		}

		total += rlen;
		if(total >= memTotal){
			break;
		}
		
		usleep(READ_FILE_DELAY); 
	}
    
    close(fd);
	
	free(data);
	
	time_t endTime = time(0);
	mylog("%s completed with clearing %d log records,time cost:%d seconds\r\n",__FUNCTION__,num,endTime - startTime);
	
    return num;
}



//#define __KMP_SEARCH__

int deleteLog(char format[SEARCH_ITEM_LIMIT][256],int count,char tag[SEARCH_ITEM_LIMIT][256],GetStringHdr_cb *GetStrHdr,
char replace[SEARCH_ITEM_LIMIT][256],int type[SEARCH_ITEM_LIMIT]) {
	int result = 0;
	
    int fd = 0;
	
	time_t startTime = time(0);
	struct tm * tm_start = localtime(&startTime);
	if(tm_start){
		mylog("%s start date time:%04d/%02d/%02d %02d:%02d:%02d\r\n",__FUNCTION__,
		tm_start->tm_year+1900,tm_start->tm_mon+1,tm_start->tm_mday,tm_start->tm_hour,tm_start->tm_min,tm_start->tm_sec);
	}
	
	unsigned long bufSize = FILE_BUFFER_SIZE;

    char *data=malloc(bufSize+TERMINAL_BUF_SIZE);
	if(data <= 0){
		perror("malloc");
		return -1;
	}
    
    fd = open("/dev/mem", O_RDWR);
    if (fd <= 0) {
        perror("open");
		free(data);
        return -1;
    }
	
	size_t memTotal = GetTotalMem();
	if(memTotal >= PHYSICAL_MEMORY_LIMIT)
	{
		memTotal = PHYSICAL_MEMORY_LIMIT;
	}
	if(memTotal < bufSize){
		mylog("memory size too small:%x\r\n",memTotal);
		//return -1;
	}
	
	off_t  filepos = 0x01000000;
	off_t  newpos = lseek(fd,filepos,SEEK_SET);
	if(filepos != newpos){
		mylog("lseek:%x error\r\n",filepos);
	}
	unsigned long total = filepos;
	
	char str[SEARCH_ITEM_LIMIT][256];
	int strSize[SEARCH_ITEM_LIMIT];
	
	int cnt = 0;
	
#ifdef __KMP_SEARCH__
	char kmpNext[SEARCH_ITEM_LIMIT][256];
	
	for(cnt = 0;cnt < count;cnt ++){
		KmpGetNext(str[cnt],kmpNext[cnt]);
	}
#endif
	//makeTestStr(str);
	result = MakeLoginTag(format,count,tag,str,strSize,type);
	
	int pagesize =  getpagesize();
	int pagemask = ~(pagesize - 1);
	
	pid_t mypid = getpid();
	char * szboundary = "this is my bundary";
	
	int num = 0;
	
	mylog("physical memory size:%x\r\n",memTotal);
	
	int findTag = 0;
		
	int delta1[SEARCH_ITEM_LIMIT][ALPHABET_LEN];
    int delta2[SEARCH_ITEM_LIMIT][ALPHABET_LEN];
	for(cnt = 0;cnt < count;cnt ++){
		make_delta1(delta1[cnt], str[cnt], strSize[cnt]);
		make_delta2(delta2[cnt], str[cnt], strSize[cnt]);
	}
    
	while(total < memTotal){
		unsigned long readSize = memTotal - total;
		unsigned long rlen = 0;
		if(readSize >= bufSize){
			readSize = bufSize;
		}
		else{
			
		}
		
		rlen =  read(fd, data, readSize);
		if(rlen <= 0 || rlen > readSize ){
			perror("read\r\n");
			break;
		}
		else if(rlen != readSize ){
			mylog("read actual size:%x\r\n",rlen);
		}
		memset(data + rlen,0,TERMINAL_BUF_SIZE);
		
		int seq = 0;
		for(seq = 0;seq < count;seq ++){
			
			uint32_t mypos = 0;
			while(mypos < rlen){
#ifdef __KMP_SEARCH__
				int pos = KmpSearch(data+mypos,rlen - mypos,str[seq],strSize[seq],kmpNext[seq]);
				if (pos == -1)
#else
				unsigned long pos = boyer_moore(data+mypos, rlen - mypos, str[seq], strSize[seq],delta1[seq],delta2[seq]);
				if (pos == 0 && chars_compared != strSize[seq] )
#endif					
				{
					break;
				}else{
					unsigned long oldPos = mypos; 
					mypos += pos;
					
					unsigned long findPos = mypos;
					mypos += strSize[seq];
					
					if( *(pid_t*)(data + mypos) == mypid
					/*&& MyStrCmp(data + mypos + strSize[seq] + sizeof(pid_t),szboundary) == 0*/ )
					{

					}
					else{
						//mylog("Found at position:%x,string:%s,chars compared:%d\r\n", findPos,data + findPos,chars_compared);
						unsigned long value[16];
						int paramCnt = GetStrHdr[seq](data + findPos,data + oldPos,value);
						if(paramCnt){
							for(cnt = 0;cnt < paramCnt;cnt ++)
							{
								unsigned long phyAddr =  total + (value[cnt] - (unsigned long) data);
								
								unsigned long hdrAlignFileOffset = phyAddr & pagemask;
								
								unsigned long hdrPageOffset = phyAddr - hdrAlignFileOffset;
								
								mylog_new("Find target string at file offset:%x,value:%s\r\n",phyAddr,(char*)value[cnt]);
								
								void *mapaddr = mmap(NULL,pagesize*2, PROT_READ | PROT_WRITE,MAP_PRIVATE , fd, hdrAlignFileOffset);
								if(mapaddr == MAP_FAILED){
									perror("mmap\r\n");
									break;
								}
								else{
									if(type[seq] == TPYE_UTF8STRING){
										
										memcpy((char*)mapaddr+hdrPageOffset,replace[seq],4);
									}
									else if(type[seq] == TYPE_INT){
										memcpy((char*)mapaddr+hdrPageOffset,replace[seq],sizeof(int));
									}
									//mylog("new address:%x,new string:%s\r\n",mapaddr+hdrPageOffset, mapaddr+hdrPageOffset);
								}
								
								num ++;
								munmap(mapaddr, pagesize);
								
								mylog_new("find target:%8d    ",num);
							}
						}
						else{
							//mylog("Not find target string header at file offset:%x,value:%s\r\n",total + idx,data + idx);
						}
					}
				}				
			}
		}
		total += rlen;
		if(total >= memTotal){
			break;
		}
		
		filepos += rlen;
		if(filepos >= memTotal){
			break;
		}
		/*
		newpos = lseek(fd,filepos,SEEK_SET);
		if(filepos != newpos){
			mylog("lseek:%x error\r\n",filepos);
		}
		
		if(findTag){
			//break;
		}
		*/
		
		usleep(READ_FILE_DELAY); 
	}
    
    close(fd);
	
	free(data);
	
	time_t endTime = time(0);
	mylog("%s completed with clearing %d log records,time cost:%d seconds\r\n",__FUNCTION__,num,endTime - startTime);
	
    return num;
}



//[Oct 23 12:08:53]: CMD-(TEL17):[show packages system]by root from vty15
//[Oct 22 19:30:50]: CMD-(SSH8):[show command-history]by admin from vty6 (172.16.0.203)
//[Oct 22 13:53:28]: CMD-(SSH4):[show system brief]by admin from vty2 (172.16.0.203)
int DeleteHistory(char * username){
	
	int ret = 0;
	
	char tag[SEARCH_ITEM_LIMIT][256];
	
	char format[SEARCH_ITEM_LIMIT][256];
	GetStringHdr_cb callback[SEARCH_ITEM_LIMIT];
	char replace[SEARCH_ITEM_LIMIT][256];
	int type[SEARCH_ITEM_LIMIT];
	
	int seq = 0;
	strcpy(tag[seq],username);
	callback[seq] = ParseCommandHistoryHeader;
	memcpy(replace[seq],"\x00\x00\x00\x00",4);
	type[seq] = TPYE_UTF8STRING;
	strcpy(format[seq++],"]by %s from ");
	
	strcpy(tag[seq],"");
	callback[seq] = ParseDummy;
	memcpy(replace[seq],"\x00\x00\x00\x00",4);
	type[seq] = TPYE_UTF8STRING;
	//strcpy(format[seq++],"\t - Repeated %s");

	ret = deleteLog(format,seq,tag,callback,replace,type);
	
	return ret;
	
}


int DeleteAddr(char * ip){
	int ret = 0;
	char tag[SEARCH_ITEM_LIMIT][256];
	
	char format[SEARCH_ITEM_LIMIT][256];
	GetStringHdr_cb callback[SEARCH_ITEM_LIMIT];
	char replace[SEARCH_ITEM_LIMIT][256];
	int type[SEARCH_ITEM_LIMIT];
	
	int seq = 0;
	if(ip){
		seq = 0;
		strcpy(tag[seq],ip);
		callback[seq] = ParseLogHeader;
		memcpy(replace[seq],"\x00\x00\x00\x00",4);
		type[seq] = TPYE_UTF8STRING;
		strcpy(format[seq++]," ( %s )");
		
		//strcpy(format[seq++],"-CONNECTION: Disconnected from %s\n");
		
		ret = deleteLog(format,seq,tag,callback,replace,type);
	}
	
	return 0;
}







int DeleteUser(char * username){
	
	int ret = 0;
	
	char tag[SEARCH_ITEM_LIMIT][256];
	
	char format[SEARCH_ITEM_LIMIT][256];
	GetStringHdr_cb callback[SEARCH_ITEM_LIMIT];
	char replace[SEARCH_ITEM_LIMIT][256];
	int type[SEARCH_ITEM_LIMIT];
	
	int seq = 0;
	strcpy(tag[seq],username);
	callback[seq] = ParseLogHeader;
	memcpy(replace[seq],"\x00\x00\x00\x00",4);
	type[seq] = TPYE_UTF8STRING;
	strcpy(format[seq++],"-LOGOUT: Exec session is terminated for user %s on line ");
	
	strcpy(tag[seq],username);
	callback[seq] = ParseLogHeader;
	memcpy(replace[seq],"\x00\x00\x00\x00",4);
	type[seq] = TPYE_UTF8STRING;
	strcpy(format[seq++],"-LOGIN_SUCCESS: Login successful for user %s on line ");
	
	strcpy(tag[seq],username);
	callback[seq] = ParseLogHeader;
	memcpy(replace[seq],"\x00\x00\x00\x00",4);
	type[seq] = TPYE_UTF8STRING;
	strcpy(format[seq++],"-CONCURRENT_LOGIN: User %s has ");
	
	ret = deleteLog(format,seq,tag,callback,replace,type);
	
	return ret;
}


int ParseDummy(char * data,char * begin,unsigned long * value){
	value[0] =(unsigned long) data;
	return 1;
}



int ReplaceMem(char * strParam){
	int ret = 0;
	
	char * sep = strstr(strParam,"-");
	if(sep){

	}
	else{
		sep = strstr(strParam,"_");
		if(sep == 0){
			return 0;
		}
	}
	char strlabel[256]={0};
	char strdata[256]={0};
	memcpy(strlabel,strParam,sep - strParam);
	strcpy(strdata,sep + 1);
	
	unsigned long label = strtoul(strlabel,0,16);
	unsigned long data = strtoul(strdata,0,16);
	
	mylog("replace label:%x with value:%x\r\n",label,data);
	
	char strip_old[256];
	char strip_new[256];
	char * addresss = inet_ntoa(label);
	strcpy(strip_old,addresss);
	addresss = inet_ntoa(data);
	strcpy(strip_new,addresss);
	mylog("replace ip:%x with ip:%x\r\n",strip_old,strip_new);
	
	char tag[SEARCH_ITEM_LIMIT][256];
	
	char format[SEARCH_ITEM_LIMIT][256];
	GetStringHdr_cb callback[SEARCH_ITEM_LIMIT];
	char replace[SEARCH_ITEM_LIMIT][256];
	
	int type[SEARCH_ITEM_LIMIT];
	
	int seq = 0;
	memcpy(tag[seq],&label,sizeof(int));
	callback[seq] = ParseDummy;
	strcpy(format[seq],"");
	type[seq] = TYPE_INT;
	memcpy(replace[seq++],&data,sizeof(int));
	
	ret = deleteLog(format,seq,tag,callback,replace,type);
	return ret;
}