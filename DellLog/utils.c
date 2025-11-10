


#include "utils.h"

#include <arpa/inet.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/wait.h>


int g_trace_log = 0;

int check_securelevel(void) {
    int securelevel;
    size_t len = sizeof(securelevel);
    
    if (sysctlbyname("kern.securelevel", &securelevel, &len, NULL, 0) == 0) {
        return securelevel;
    }
    return -1;
}



int isIPAddr(char * strparam){
	int len = strlen(strparam);
	char str[64];
	if(len >= sizeof(str))
	{
		return 0;
	}
	strcpy(str,strparam);
	
	uint32_t ip_num = inet_addr(str);
	if(ip_num == INADDR_NONE || ip_num == 0xffffffff){
		return 0;
	}
	
	
	
	int i = 0;
	int j = 0;
	
	for(i = 0,j = 0;i < len; ){
		if( (str[i] >= '0' && str[i] <= '9') || str[i] == '.' )
		{
			str[j] = str[i];
			j ++;
			i ++;
		}
		else if(str[i] == ' '){
			i ++;
		}
		else{
			return 0;
		}
	}
	str[j] = 0;
	printf("remove space result:%s\r\n",str);
	
	len = strlen(str);
	if(len > 16){
		return 0;
	}
	
	int cnt = 0;
	char buf[4] = {0};
	for( i = 0,j = 0;i < len;i ++){
		if(str[i] >= '0' && str[i] <= '9'){
			buf[j] = str[i];
			j ++;
			if( j >= 1 && j <= 3 )
			{
				if( (str[i +1] == '.' && cnt <= 2) || (str[i+1] == 0 && cnt == 3) ){
					int seg = atoi(buf);
					if(seg >= 0 && seg <= 255){
						j = 0;
						memset(buf,0,sizeof(buf));
						cnt ++;
						i ++;
					}else{
						return 0;
					}
				}
				else if(j >= 3){
					return 0;
				}
				else{

				}
			}
			else if(j > 3){
				return 0;
			}
			else{
				return 0;
			}
		}
		else{
			break;
		}
	}
	
	if(cnt >= 3){
		return 1;
	}
	return 0;
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
		printf("%s fork child pid:%x, pid_t:%x\r\n",__FUNCTION__,pid,getpid());

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
            fprintf(stderr, "cmd exec error：%d\n", WEXITSTATUS(status));
        }	
	}
	return ret;
}



int DelayExec(int sec,delay_callback func,char * param){
	int ret = 0;
	pid_t pid = fork();
	if(pid < 0){
		perror("fork\r\n");
		ret = -1;		
	}else if(pid == 0){
		sleep(sec);
			
		ret = func(param);

		printf("%s exec with parameter:%s complete\r\n",__FUNCTION__,param);
		
		exit(0);

	}else {
		printf("%s pid:%x pid_t:%x\r\n",__FUNCTION__,pid,getpid());
	}
	return ret;
}


void myFile(char * data,int size) {
	if(g_trace_log){
		int ret = 0;
		
		FILE *log_file = fopen(MY_LOG_DATA_FILE, "ab+");
		if (log_file == NULL) {
			fprintf(stderr, "open log file: %s\r\n", strerror(errno));
			return;
		}
		
		time_t now = time(NULL);
		char timestamp[64];
		strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
		//fprintf(log_file, "[%s] ", timestamp);

		char * datahdr = "data:[\r\n\r\n";
		ret = fwrite(datahdr,strlen(datahdr),1,log_file);

		ret = fwrite(data,size,1,log_file);
		char * datatail = "\r\n\r\n]data\r\n\r\n";
		ret = fwrite(datatail,strlen(datatail),1,log_file);
		
		fclose(log_file);
		if(ret <= 0){
			printf("%s error\r\n",__FUNCTION__);
		}
	}
}


void myLogFile(char * format, ...) {
	
	char buf[0x1000];
	
    va_list ap;     

    va_start(ap, format);  

	vsnprintf(buf,sizeof(buf),format, ap);

    va_end(ap);  
	
	FILE *log_file = fopen(MY_LOG_FILE, "ab+");
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
	
    va_list ap;     

    va_start(ap, format);  

	vprintf(format, ap);

    va_end(ap); 
}

void mylog_new(char * format, ...) {
	
	if(g_trace_log){
		
		va_list ap;     

		va_start(ap, format); 

		vprintf(format, ap);

		va_end(ap);  
	}
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