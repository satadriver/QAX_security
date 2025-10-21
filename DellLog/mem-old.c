
#include "mem.h"
#include <time.h>



char * getLineHeader(char * data){
	while(*data -- != '\n');
	return data+2;	
}


//buffer overflow
char* PartialCompare(char * format,char * data){
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


char * getLogHeader(char * data,char * begin)
{

	char month[16];
	
	char day[16];
	
	char hour[16];
	
	char minute[16];
	
	char second[16];
	
	char str[1024+1];
	
	int size = 0;
	
	while(1){
		if(data < begin)
		{
			
			break;
		}
		
		if(*data == '\n' || *data == 0){
			break;
		}
		
		int cnt = sscanf(data,"%3s %2s %2s:%2s:%2s %1024s",month,day,hour,minute,second,str);
		if(cnt == 6){
			if(strlen(month) == 3 && strlen(day) == 2 && strlen(hour) == 2&& strlen(minute) == 2&& strlen(second) == 2){
				return data;
			}
			else{
				//continue;
			}
		}
		
		data --;
		size ++;
		if(size >=1024){
			break;
		}
	}
		
	return 0;
}




int makeLoginTag(char format[SEARCH_ITEM_LIMIT][256],int count,char * tag,char str[SEARCH_ITEM_LIMIT][1024],int *strSize)
{
	pid_t mypid = getpid();
	char * szboundary = "this is my bundary";

	int total = 0;
	int i = 0;
	for( i = 0;i < count;i ++){
		int length = sprintf(str[i],format[i],tag);
		
		int len = strlen(str[i]);
		
		strSize[i] = len;
			
		memcpy(str[i] + strSize[i] + 1,&mypid,sizeof(pid_t));
		strcpy(str[i] + strSize[i] + 1 + sizeof(pid_t),szboundary);
		
		//printf("str[%d]:%s\r\n",i,str[i]);
		
		total ++;
	}
	
	return total;
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


int DeleteAddr(char * ip){
	int ret = 0;
	char format[SEARCH_ITEM_LIMIT][256];
	int seq = 0;
	if(ip){
		seq = 0;
		 strcpy(format[seq++]," ( %s )");
		//strcpy(format[seq++],"-CONNECTION: Disconnected from %s\n");
		ret = deleteLog(format,seq,ip);
	}
	
	return 0;
}


int DeleteDateTime(time_t start,time_t stop){
	if(stop == -1 ){
		stop = time(0);
	}
	
	start = time(0) - start * 3600;
	stop = time(0) - stop * 3600;
	
	if(start == 0 || stop == 0 || start >= stop){
		return 0;
	}
	
	struct tm * tm_begin = localtime(start);
	struct tm * tm_end = localtime(stop);
	
	char startstr[256];
	char endstr[256];
	
	const char * startmon = GetMonthStr(tm_begin->tm_mon);
	const char * endmon = GetMonthStr(tm_end->tm_mon);
	int startlen = sprintf(startstr,"%s %2d %2d:%2d:%2d",
	startmon,tm_begin->tm_mday+1,tm_begin->tm_hour,tm_begin->tm_min,tm_begin->tm_sec);
	int endlen = sprintf(endstr,"%s %2d %2d:%2d:%2d",
	endmon,tm_end->tm_mday+1,tm_end->tm_hour,tm_end->tm_min,tm_end->tm_sec);
	int result = 0;
	
	int ret = 0;
	
    int fd = 0;
	
	int bufsize = FILE_BUFFER_SIZE;

    char *data=malloc(bufsize+TERMINAL_BUF_SIZE);
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
	
	unsigned int total = 0;
	
	int pagesize =  getpagesize();
	int pagemask = ~(pagesize - 1);
	
	int num = 0;
    
	while(1){
		
		int rlen =  read(fd, data, bufsize);
		if(rlen <= 0 || rlen > bufsize ){
			perror("read\r\n");
			break;
		}
		
		if(rlen != bufsize ){
			printf("read actual size:%d\r\n",rlen);
		}
		memset(data + rlen,0,TERMINAL_BUF_SIZE);
		
		int idx = 0;
		for(idx = 0;idx <= rlen-1;idx++){
			char * c = data + idx;
			if( c[3] == ' '&& c[6] == ' '&& c[9] == ':'&& c[12] == ':' && c[15] == ' ' && memcmp(c+16,"%STKUNIT",8) == 0)
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
							
							result = memcmp(c + 4,startstr + 4,11);
							if(result >= 0){
								ret = memcmp(c + 4,endstr + 4,11);
								if(ret <= 0){
									
									//printf("Find target string at file offset:%x,value:%s\r\n",lineHdr,lineHdr);
					
									unsigned int hdrOffset = (total + idx) & pagemask;
									
									int hdrPageOffset = (total + idx) - hdrOffset;
									
									void *mapaddr = mmap(NULL,pagesize, PROT_READ | PROT_WRITE,MAP_PRIVATE , fd, hdrOffset);
									if(mapaddr == MAP_FAILED){
										perror("mmap\r\n");
										break;
									}
									else{								
										memcpy((char*)mapaddr+hdrPageOffset,"\x00\x00\x00\x00",4);
										//printf("new address:%x,new string:%s\r\n",mapaddr+hdrPageOffset, mapaddr+hdrPageOffset);
									}
									
									num ++;
									munmap(mapaddr, pagesize);						
								}
							}
						}
					}
				}
			}
		}

		total += rlen;
		if(total >= 0xc0000000){
			break;
		}	
	}
    
    close(fd);
	
	free(data);
	
	//printf("%s completed with clearing %d log records\r\n",__FUNCTION__,num);
	
    return 0;
}


int DeleteUser(char * username){
	
	int ret = 0;
	/*
	ret = deleteLog("-LOGOUT: Exec session is terminated for user %s on line ","admin");
	ret = deleteLog("-LOGIN_SUCCESS: Login successful for user %s on line ","admin");
	ret = deleteLog("-CONCURRENT_LOGIN: User %s has ","admin");
	if(ip){
		ret = deleteLog("-CONNECTION: Disconnected from %s\n",ip);
	}
	*/
	
	char format[SEARCH_ITEM_LIMIT][256];
	int seq = 0;
	strcpy(format[seq++],"-LOGOUT: Exec session is terminated for user %s on line ");
	strcpy(format[seq++],"-LOGIN_SUCCESS: Login successful for user %s on line ");
	strcpy(format[seq++],"-CONCURRENT_LOGIN: User %s has ");
	
	ret = deleteLog(format,seq,username);
	
	return ret;
}


#include <stdint.h>
#include <stdbool.h>


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

uint32_t boyer_moore (uint8_t *string, uint32_t stringlen, uint8_t *pat, uint32_t patlen) {
    int i;
    int delta1[ALPHABET_LEN];
    int *delta2 = malloc(patlen * sizeof(int));
    make_delta1(delta1, pat, patlen);
    make_delta2(delta2, pat, patlen);
    int n_shifts = 0;
    chars_compared = 0;

    i = patlen-1;
    while (i < stringlen) {
        int j = patlen-1;
        while (j >= 0 && (string[i] == pat[j])) {
            --i;
            --j;
            chars_compared++;
        }
        if (j < 0) {
            free(delta2);
            return (uint32_t) i+1;
        }
        chars_compared++;
        i += max(delta1[string[i]], delta2[j]);
    }
    free(delta2);
    return 0;
}



int deleteLog(char format[SEARCH_ITEM_LIMIT][256],int count,char * tag) {
	int result = 0;
	
    int fd = 0;
	
	int bufsize = FILE_BUFFER_SIZE;

    char *data=malloc(bufsize+TERMINAL_BUF_SIZE);
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
	
	unsigned int total = 0;
	
	char str[SEARCH_ITEM_LIMIT][1024];
	int strSize[SEARCH_ITEM_LIMIT];
	//makeTestStr(str);
	result = makeLoginTag(format,count,tag,str,strSize);
	
	int pagesize =  getpagesize();
	int pagemask = ~(pagesize - 1);
	
	pid_t mypid = getpid();
	char * szboundary = "this is my bundary";
	
	int num = 0;
    
	while(1){
		
		int rlen =  read(fd, data, bufsize);
		if(rlen <= 0 || rlen > bufsize ){
			perror("read\r\n");
			break;
		}
		
		if(rlen != bufsize ){
			printf("read actual size:%d\r\n",rlen);
		}
		memset(data + rlen,0,TERMINAL_BUF_SIZE);
		int seq = 0;
		for( seq = 0;seq < count;seq ++){
			uint32_t pos = boyer_moore(data, rlen, str[seq], strSize[seq]);
      		if (pos == 0 && chars_compared != strSize[seq] ){
        	  	// printf("Not Found - ");
      		}else{
        	  	printf("Found at position %u,string:%s ", pos,data + pos);
				printf("%d chars compared.\n", chars_compared);
      		}
		}
		
		total += rlen;
		if(total >= 0xc0000000){
			break;
		}	
	}
    
    close(fd);
	
	free(data);
	
	//printf("%s completed with clearing %d log records\r\n",__FUNCTION__,num);
	
    return 0;
}