


#include "utils.h"

#include <arpa/inet.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/wait.h>

int check_securelevel(void) {
    int securelevel;
    size_t len = sizeof(securelevel);
    
    if (sysctlbyname("kern.securelevel", &securelevel, &len, NULL, 0) == 0) {
        return securelevel;
    }
    return -1;
}



int isIPAddr(char * str){
	uint32_t ip_num = inet_addr(str);
	if(ip_num == INADDR_NONE){
		return 0;
	}
	return 1;
}


int DeleteFileName(char * fn){
	return unlink (fn);
	
}

const char * month[12] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};

const char* GetMonthStr(int num){

	if(num > 12 || num < 0){
		return 0;
	}
	
	return month[num];
}


int GetMonthNum(char * strmonth){
	
	int num = 0;
	for( num = 0;num < 12; num ++){
		if(memcmp(month[num],strmonth,3) == 0){

			return num;
		}
	}
	return -1;
}


int CmpMonth(char * first,char * second){
	
	int num1,num2;
	
	num1 = GetMonthNum(first);
	num2 = GetMonthNum(second);
	
	return num1- num2;
	
}


int DeleteSelf(){
	
	int ret = 0;

	char fp[0x1000];
	char * path = getcwd(fp,sizeof(fp));
	char * progname = getprogname();
	strcat(fp,"/");
	strcat(fp,progname);
	
	ret = DeleteFileName(fp);
	return ret;
}



int exec(char * cmd){
	int ret = 0;
	pid_t pid = fork();
	if(pid < 0){
		perror("fork\r\n");
		ret = -1;
		
	}else if(pid == 0){
		execlp("/bin/sh","sh","-c",cmd,0);		
		//the last param end with null
		//if execlp function call success,this line of code has no return value
		
		printf("execlp failed\r\n");
		exit(127);
	}else {
		printf("%s pid:%x pid_t:%x\r\n",__FUNCTION__,pid,getpid());

		int status;
        while (waitpid(pid, &status, 0) == -1) {
            if (errno != EINTR) { 
                perror("waitpid failed");
                return ret;
            }
        }
        
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            ret = 0;  
        } else {
            fprintf(stderr, "命令执行失败，退出状态：%d\n", WEXITSTATUS(status));
        }
		
	}
	return ret;
}



void myLogFile(char * format, ...) {
	
	char buf[0x1000];
	
    va_list ap;     

    va_start(ap, format);  

	vsnprintf(buf,sizeof(buf),format, ap);

    va_end(ap);  
	
	FILE *log_file = fopen(LOG_FILE, "ab+");
    if (log_file == NULL) {
        fprintf(stderr, "open log file: %s\r\n", strerror(errno));
        return;
    }
    
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    fprintf(log_file, "[%s] ERROR: %s\r\n", timestamp, buf);
    fclose(log_file);
}



void mylog(char * format, ...) {
	
	//return;
	
    va_list ap;     

    va_start(ap, format);  

	vprintf(format, ap);

    va_end(ap);  
}

void mylog_new(char * format, ...) {
	
	return;
	
    va_list ap;     

    va_start(ap, format);  

	vprintf(format, ap);

    va_end(ap);  
}

size_t GetTotalMem() {

    int mib[2] = {CTL_HW, HW_PHYSMEM};
    size_t physmem = 0;   
    size_t len = sizeof(physmem); 

    if (sysctl(mib, 2, &physmem, &len, 0, 0) == -1) {
        return 0;
    }

    return physmem;
}

int MyMemCmp(char * str1,char * str2,int len){
	
	int i = 0;
	for( i = 0;i < len;i ++){
		if(str1[i] == str2[i]){
			
		}
		else{
			return str1[i] - str2[i];
		}
	}
	return 0;
}


int MyStrLen(char * str){
	char * mystr = str;
	while( *mystr ++);
	
	return mystr - str - 1;
}


int MyStrCmp(char * str1,char * str2){
	
	int len1 = MyStrLen(str1);
	int len2 = MyStrLen(str2);
	
	int len = (len1 > len2 )? len2:len1;
	int i = 0;

	for( i = 0;i < len+1;i ++){
		if(str1[i] == str2[i]){
			
		}
		else{
			return str1[i] - str2[i];
		}
	}
	return 0;
}